use super::{
    config::SsConfig,
    tcprelay::{
        copy_into::copy_into,
        crypto_io::{AeadDecryptedReader, AeadEncryptorWriter},
        socks5,
    },
};
use bytes::Bytes;
use futures::{executor::ThreadPoolBuilder, future::FutureObj, prelude::*, select, task::Spawn};
use log::{debug, info};
use romio::tcp::{TcpListener, TcpStream};
use std::{boxed::Box, path::Path, sync::Arc};

async fn run_shadowsock_connection(shared_conf: Arc<SsConfig>, stream: TcpStream) {
    if shared_conf.timeout().is_some() {
        stream.set_keepalive(shared_conf.timeout()).unwrap();
    }

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

    let mut remote_stream = match await!(TcpStream::connect(&shared_conf.ss_server_addr())) {
        Ok(s) => s,
        Err(e) => {
            debug!("connect ss server failed {}", e);
            return;
        }
    };

    let local_salt = shared_conf.method().gen_salt();
    if let Err(e) = await!(remote_stream.write_all(&local_salt[..])) {
        debug!("write local salt to remote stream failed {}", e);

        return;
    }

    let remote_salt = {
        let mut buf = [0u8; 128];
        match await!(remote_stream.read(&mut buf[..])) {
            Ok(n) => {
                if n == shared_conf.method().salt_len() {
                    Bytes::from(&buf[0..n])
                } else {
                    debug!(
                        "recv remote salt error, need {} bytes, but {} bytes",
                        shared_conf.method().salt_len(),
                        n
                    );

                    return;
                }
            }

            Err(e) => {
                debug!("recve remote salt error {}", e);

                return;
            }
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
    let mut l2r = copy_into(&mut lr, &mut enc_writer);
    let mut r2l = copy_into(&mut dec_reader, &mut lw);
    // let (mut rr, mut rw) = remote_stream.split();
    // let mut l2r = copy_into(&mut lr, &mut rw);
    // let mut r2l = copy_into(&mut rr, &mut lw);
    loop {
        select! {
            _ = l2r => {},
            _ = r2l => {},
            complete => {
                break;
            },
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
        let listener = TcpListener::bind(&self.config.listen_addr())
            .unwrap_or_else(|e| panic!("listen on {} failed {}", self.config.listen_addr(), e));
        let mut incoming = listener.incoming();
        info!("Listening on: {}", self.config.listen_addr());
        while let Some(Ok(stream)) = await!(incoming.next()) {
            let fut = run_shadowsock_connection(self.config.clone(), stream);
            threadpool.spawn_obj(FutureObj::new(Box::pin(fut))).unwrap();
        }
    }
}
