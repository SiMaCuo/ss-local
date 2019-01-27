// use super::conn::{self, *};
use super::{config::SsConfig, tcprelay::socks5};

// use super::rccell::*;
// use super::shut::*;
use futures::{executor::ThreadPoolBuilder, future::FutureObj, prelude::*, task::Spawn};
use log::{debug, info};
use romio::tcp::{TcpListener, TcpStream};
use std::{
    boxed::Box,
    io::Result,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

// const LISTENER: Token = Token(0);
async fn run_shadowsock_connection(shared_conf: Arc<SsConfig>, stream: TcpStream) {
    if shared_conf.keeplive.is_some() {
        stream.set_keepalive(shared_conf.keeplive).unwrap();
    }

    let (r, w) = stream.split();
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
            .pool_size(self.config.local_threadpool_size)
            .create()
            .unwrap();
        let listener = TcpListener::bind(&self.config.local_addr)
            .unwrap_or_else(|e| panic!("listen on {} failed {}", self.config.local_addr, e));
        let mut incoming = listener.incoming();
        info!("Listening on: {}", self.config.local_addr);
        while let Some(Ok(stream)) = await!(incoming.next()) {
            let fut = run_shadowsock_connection(self.config.clone(), stream);
            threadpool.spawn_obj(FutureObj::new(Box::pin(fut))).unwrap();
        }
    }
}
