use super::{
    config::SsConfig,
    tcprelay::{
        copy_into::copy_into,
        crypto_io::{AeadDecryptedReader, AeadEncryptorWriter},
        socks5::{self, s5code, Address, Reply, SOCKS5_VERSION},
    },
};
use crate::crypto::cipher::CipherMethod;
#[cfg(target_os = "windows")]
use crate::fc::acl::AclResult;
use bytes::Bytes;
use futures::{
    executor::ThreadPoolBuilder,
    future::FutureObj,
    io::{ReadHalf, WriteHalf, AsyncWriteExt},
    prelude::*,
    select,
    task::Spawn,
};
use log::{debug, info};
use romio::tcp::{TcpListener, TcpStream};
use std::{
    boxed::Box,
    io,
    marker::Unpin,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{atomic::AtomicUsize, Arc},
};

#[cfg(target_os = "windows")]
fn acl_match_address(conf: &SsConfig, address: &socks5::Address) -> AclResult {
    match address {
        Address::SocketAddr(sock_addr) => {
            if sock_addr.ip().is_loopback()
                || sock_addr.ip().is_multicast()
                || sock_addr.ip().is_unspecified()
                || sock_addr.ip().is_documentation()
            {
                return AclResult::Reject;
            }

            match sock_addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    if ip.is_private() {
                        return AclResult::Reject;
                    }
                }

                std::net::IpAddr::V6(ip) => {
                    if ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_unicast_site_local() {
                        return AclResult::Reject;
                    }
                }
            }

            return AclResult::ByPass;
        }

        Address::DomainName(ref domain, _) => return conf.acl_match(&domain),
    }
}

async fn connect_sserver<'a, W>(addr: SocketAddr, w: &'a mut W) -> io::Result<TcpStream>
where
    W: AsyncWriteExt + Unpin,
{
    let succ = [
        SOCKS5_VERSION,
        Reply::Succeeded.as_u8(),
        0,
        s5code::SOCKS5_ADDRTYPE_V4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];

    let mut fail = [
        SOCKS5_VERSION,
        Reply::GeneralFailure.as_u8(),
        0,
        s5code::SOCKS5_ADDRTYPE_V4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];

    match TcpStream::connect(&addr).await {
        Ok(s) => {
            let _ = w.write_all(&succ).await;
            Ok(s)
        }

        Err(e) => {
            #[cfg_attr(rustfmt, rustfmt_skip)]
            let code = match e.kind() {
                io::ErrorKind::ConnectionRefused    => Reply::ConnectRefused,
                io::ErrorKind::ConnectionAborted    => Reply::ConnectDisallowed,
                _                                   => Reply::NetworkUnreachable,
            };
            fail[1] = code.as_u8();

            let _ = w.write_all(&fail).await;
            Err(e)
        }
    }
}

async fn exchange_salt(remote_stream: &mut TcpStream, m: CipherMethod) -> io::Result<(Bytes, Bytes)> {
    let local_salt = m.gen_salt();
    if let Err(e) = remote_stream.write_all(&local_salt[..]).await {
        debug!("write local salt to remote stream failed {}", e);

        return Err(e);
    }

    let remote_salt = {
        let mut buf = [0u8; 128];
        match remote_stream.read(&mut buf[..]).await {
            Ok(n) => {
                if n == m.salt_len() {
                    Bytes::from(&buf[0..n])
                } else {
                    debug!("recv remote salt error, need {} bytes, but {} bytes", m.salt_len(), n);

                    return Err(io::ErrorKind::InvalidData.into());
                }
            }

            Err(e) => {
                debug!("recve remote salt error {}", e);

                return Err(e);
            }
        }
    };

    Ok((local_salt, remote_salt))
}

async fn proxy_shadowsock<'a>(
    shared_conf: &'a SsConfig,
    lr: &'a mut ReadHalf<TcpStream>,
    lw: &'a mut WriteHalf<TcpStream>,
    address: &'a Address,
    url: &'a [u8],
) {
    let mut remote_stream = match connect_sserver(shared_conf.ss_server_addr(), lw).await {
        Ok(s) => {
            if shared_conf.keepalive().is_some() {
                s.set_keepalive(shared_conf.keepalive()).unwrap();
            }
            s
        }

        Err(e) => {
            debug!("connect ss server failed {}", e);
            return;
        }
    };
    let peer_addr = remote_stream.local_addr().unwrap();
    let (local_salt, remote_salt) = match exchange_salt(&mut remote_stream, shared_conf.method()).await {
        Ok((ls, rs)) => (ls, rs),
        Err(e) => {
            debug!("exchange salt failed: {}", e);
            return;
        }
    };

    let (rr, rw) = remote_stream.split();
    let mut enc_writer = AeadEncryptorWriter::new(
        rw,
        shared_conf.method(),
        shared_conf.key_derived_from_pass(),
        local_salt,
    );

    if let Err(e) = enc_writer.write_all(&url[..]).await {
        debug!("encrypt write url to ss server failed: {}", e);

        return;
    }

    let mut dec_reader = AeadDecryptedReader::new(
        rr,
        shared_conf.method(),
        shared_conf.key_derived_from_pass(),
        remote_salt,
    );

    let host_name = format!("{:?}", address);
    proxy_copy(
        lr,
        lw,
        &mut dec_reader,
        &mut enc_writer,
        &host_name,
        &peer_addr
    ).await;
}

async fn proxy_http<'a>(lr: &'a mut ReadHalf<TcpStream>, lw: &'a mut WriteHalf<TcpStream>, address: &'a Address) {
    match address.connect(lw).await {
        Ok(remote_stream) => {
            let host_name = format!("{:?}", address);
            let peer_addr = remote_stream.local_addr().unwrap();
            let (mut rr, mut rw) = remote_stream.split();
            proxy_copy(lr, lw, &mut rr, &mut rw, &host_name, &peer_addr).await;
        }

        Err(e) => {
            debug!("{:?} proxy_http failed {:?}", address, e);
        }
    }
}

async fn proxy_copy<'a, R, W>(
    local_read: &'a mut ReadHalf<TcpStream>,
    local_write: &'a mut WriteHalf<TcpStream>,
    remote_read: &'a mut R,
    remote_write: &'a mut W,
    host_name: &'a str,
    peer_addr: &'a SocketAddr,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    debug!("{} <- {}, two-way copying", host_name, peer_addr);
    let mark = Arc::new(AtomicUsize::new(1));
    let mut l2r = copy_into(
        local_read,
        remote_write,
        mark.clone(),
        format!("{} <- {}", host_name, peer_addr),
    );
    let mut r2l = copy_into(
        remote_read,
        local_write,
        mark.clone(),
        format!("{} -> {}", host_name, peer_addr),
    );
    loop {
        select! {
            _ = l2r => { let _ = l2r.close().await; },
            _ = r2l => { let _ = r2l.close().await; },
            complete => {
                debug!("{} <-> {} total done", host_name, peer_addr);
                break;
            },
        }
    }
}

async fn run_socks5_connection(shared_conf: Arc<SsConfig>, stream: TcpStream) {
    let (mut lr, mut lw) = stream.split();
    if let Some(e) = socks5::Socks5HandShake::deal_with(&mut lr, &mut lw).await {
        debug!("local socks5 handshake failed {}", e);

        return;
    }

    let mut url = [0u8; 320];
    let url_len = match socks5::TcpConnect::deal_with(&mut lr, &mut lw, &mut url[..]).await {
        Ok(n) => n,
        Err(e) => {
            info!("local socks5 read address failed {}", e);

            return;
        }
    };

    let address = socks5::ReadAddress::read_from(&url[3..url_len]).unwrap();
    #[cfg(target_os = "windows")]
    {
        match acl_match_address(&shared_conf, &address) {
            AclResult::Reject => debug!("{:?} reject", address),
            AclResult::ByPass => {
                debug!("{:?} bypass", address);
                proxy_http(&mut lr, &mut lw, &address).await;
            }
            AclResult::RemoteProxy => {
                info!("{:?}, proxy", address);
                proxy_shadowsock(
                    &shared_conf,
                    &mut lr,
                    &mut lw,
                    &address,
                    &url[..url_len]
                ).await;
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        proxy_shadowsock(
            &shared_conf,
            &mut lr,
            &mut lw,
            &address,
            &url[..url_len]
        ).await;
    }
}

pub struct Service {
    config: Arc<SsConfig>,
}

impl Service {
    pub fn new(dir: PathBuf, conf: &Path) -> io::Result<Self> {
        SsConfig::new(dir, conf).and_then(|c| {
            let srv = Service { config: Arc::new(c) };

            Ok(srv)
        })
    }

    pub async fn serve(&mut self) {
        let mut threadpool = ThreadPoolBuilder::new()
            .pool_size(self.config.romio_threadpool_size())
            .create()
            .unwrap();
        let mut listener = TcpListener::bind(&self.config.listen_addr())
            .unwrap_or_else(|e| panic!("listen on {} failed {}", self.config.listen_addr(), e));
        let mut incoming = listener.incoming();
        println!("Listening on: {}", self.config.listen_addr());
        info!("Listening on: {}", self.config.listen_addr());
        while let Some(Ok(stream)) = incoming.next().await {
            let fut = run_socks5_connection(self.config.clone(), stream);
            threadpool.spawn_obj(FutureObj::new(Box::pin(fut))).unwrap();
        }
    }
}
