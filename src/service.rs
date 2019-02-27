use super::{
    config::SsConfig,
    tcprelay::{
        copy_into::copy_into,
        crypto_io::{AeadDecryptedReader, AeadEncryptorWriter},
        socks5::{self, s5code, Reply, SOCKS5_VERSION},
    },
};
use crate::crypto::cipher::CipherMethod;
use bytes::Bytes;
use futures::{executor::ThreadPoolBuilder, future::FutureObj, prelude::*, select, task::Spawn};
use log::{debug, info};
use romio::tcp::{TcpListener, TcpStream};
use std::{
    boxed::Box,
    io,
    net::SocketAddr,
    path::Path,
    sync::{atomic::AtomicUsize, Arc},
};

async fn connect_sserver<'a, W>(addr: SocketAddr, w: &'a mut W) -> io::Result<TcpStream>
where
    W: AsyncWriteExt,
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

    match await!(TcpStream::connect(&addr)) {
        Ok(s) => {
            let _ = await!(w.write_all(&succ));
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

            let _ = await!(w.write_all(&fail));
            Err(e)
        }
    }
}

async fn exchange_salt(remote_stream: &mut TcpStream, m: CipherMethod) -> io::Result<(Bytes, Bytes)> {
    let local_salt = m.gen_salt();
    if let Err(e) = await!(remote_stream.write_all(&local_salt[..])) {
        debug!("write local salt to remote stream failed {}", e);

        return Err(e);
    }

    let remote_salt = {
        let mut buf = [0u8; 128];
        match await!(remote_stream.read(&mut buf[..])) {
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

async fn run_shadowsock_connection(shared_conf: Arc<SsConfig>, stream: TcpStream) {
    let (mut lr, mut lw) = stream.split();
    if let Some(e) = await!(socks5::Socks5HandShake::deal_with(&mut lr, &mut lw)) {
        debug!("local socks5 handshake failed {}", e);

        return;
    }

    let mut url = [0u8; 320];
    let url_len = match await!(socks5::TcpConnect::deal_with(&mut lr, &mut lw, &mut url[..])) {
        Ok(n) => n,
        Err(e) => {
            debug!("local socks5 read address failed {}", e);

            return;
        }
    };

    let mut remote_stream = match await!(connect_sserver(shared_conf.ss_server_addr(), &mut lw)) {
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
    let (local_salt, remote_salt) = match await!(exchange_salt(&mut remote_stream, shared_conf.method())) {
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

    if let Err(e) = await!(enc_writer.write_all(&url[..url_len])) {
        debug!("encrypt write url to ss server failed: {}", e);

        return;
    }

    let mut dec_reader = AeadDecryptedReader::new(
        rr,
        shared_conf.method(),
        shared_conf.key_derived_from_pass(),
        remote_salt,
    );

    let address = socks5::ReadAddress::read_from(&url[3..url_len]).unwrap();
    let host_name = format!("{:?}", address);
    {
        debug!("{} <- {}, connect", host_name, peer_addr);
        let mark = Arc::new(AtomicUsize::new(1));
        let mut l2r = copy_into(
            &mut lr,
            &mut enc_writer,
            mark.clone(),
            format!("{} <- {}", host_name, peer_addr),
        );
        let mut r2l = copy_into(
            &mut dec_reader,
            &mut lw,
            mark.clone(),
            format!("{} -> {}", host_name, peer_addr),
        );
        loop {
            select! {
                _ = l2r => { },
                _ = r2l => { },
                complete => {
                    let _ = await!(l2r.close());
                    let _ = await!(r2l.close());
                    debug!("{} <-> {} total done", host_name, peer_addr);
                    break;
                },
            }
        }
    }
}

pub struct Service {
    config: Arc<SsConfig>,
}

impl Service {
    pub fn new() -> Self {
        Service {
            config: Arc::new(SsConfig::new(Path::new("./config.json")).unwrap()),
        }
    }

    pub async fn serve(&mut self) {
        let mut threadpool = ThreadPoolBuilder::new()
            .pool_size(self.config.romio_threadpool_size())
            .create()
            .unwrap();
        let mut listener = TcpListener::bind(&self.config.listen_addr())
            .unwrap_or_else(|e| panic!("listen on {} failed {}", self.config.listen_addr(), e));
        let mut incoming = listener.incoming();
        info!("Listening on: {}", self.config.listen_addr());
        while let Some(Ok(stream)) = await!(incoming.next()) {
            let fut = run_shadowsock_connection(self.config.clone(), stream);
            threadpool.spawn_obj(FutureObj::new(Box::pin(fut))).unwrap();
        }
    }
}
