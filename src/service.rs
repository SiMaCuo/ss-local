use super::{
    config::SsConfig,
    leakybuf::LeakyBuf,
    tcprelay::{
        copy_into::copy_into,
        crypto_io::{AeadDecryptedReader, AeadEncryptorWriter},
        socks5,
    },
};
use futures::{executor::ThreadPoolBuilder, future::FutureObj, prelude::*, select, task::Spawn};
use log::{debug, info};
use romio::tcp::{TcpListener, TcpStream};
use std::{boxed::Box, path::Path, sync::Arc};

async fn run_shadowsock_connection(shared_conf: Arc<SsConfig>, l: Arc<LeakyBuf>, stream: TcpStream) {
    if shared_conf.timeout().is_some() {
        stream.set_keepalive(shared_conf.timeout()).unwrap();
    }

    let (mut lr, mut lw) = stream.split();
    let address = {
        let mut leaky = l.get();
        if let Some(e) = await!(socks5::Socks5HandShake::deal_with(&mut lr, &mut lw, &mut leaky)) {
            debug!("local socks5 handshake failed {}", e);

            return;
        }

        match await!(socks5::TcpConnect::deal_with(&mut lr, &mut lw, &mut leaky)) {
            Ok(address) => address,
            Err(e) => {
                debug!("local socks5 read address failed {}", e);

                return;
            }
        }
    };

    let remote_stream = match await!(address.connect(&mut lw)) {
        Ok(stream) => stream,
        Err(e) => {
            debug!("connect failed {}", e);
            return;
        }
    };

    println!("connected {}", remote_stream.peer_addr().unwrap());
    // let (rr, rw) = remote_stream.split();
    // let mut enc_writer = AeadEncryptorWriter::new(
    //     rw,
    //     shared_conf.method(),
    //     shared_conf.key_derived_from_pass(),
    //     shared_conf.method().gen_salt(),
    // );
    // let mut dec_reader = AeadDecryptedReader::new(
    //     rr,
    //     shared_conf.method(),
    //     shared_conf.key_derived_from_pass(),
    //     shared_conf.method().gen_salt(),
    // );
    // let mut l2r = copy_into(&mut lr, &mut enc_writer);
    // let mut r2l = copy_into(&mut dec_reader, &mut lw);
    let (mut rr, mut rw) = remote_stream.split();
    let mut l2r = copy_into(&mut lr, &mut rw);
    let mut r2l = copy_into(&mut rr, &mut lw);
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
        let leakybuf = Arc::new(LeakyBuf::new(300, 64));
        while let Some(Ok(stream)) = await!(incoming.next()) {
            let fut = run_shadowsock_connection(self.config.clone(), leakybuf.clone(), stream);
            threadpool.spawn_obj(FutureObj::new(Box::pin(fut))).unwrap();
        }
    }
}
