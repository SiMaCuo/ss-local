// use super::conn::{self, *};
use super::{config::SsConfig, socks5::*};
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

// pub struct Service {
//     conns: Slab<RcCell<Connection>>,
//     poll: Poll,
//     config: Config,
// }
//
// impl Service {
//     pub fn new() -> Self {
//         Service {
//             conns: Slab::with_capacity(1024),
//             poll: Poll::new().unwrap(),
//             config: Config::new(Path::new("./config.json")).unwrap(),
//         }
//     }
//
//     fn stats(&self) {
//         let mut conn_kes: Vec<(usize, usize)> = Vec::with_capacity(128);
//         let mut mem: f32 = 0.0;
//         let mut v: Vec<String> = Vec::new();
//         v.push("\n".to_string());
//         for (_, cnt) in &self.conns {
//             let key = (
//                 cnt.borrow().get_token(LOCAL).0,
//                 cnt.borrow().get_token(REMOTE).0,
//             );
//             if conn_kes.contains(&key) {
//                 continue;
//             }
//             conn_kes.push(key);
//
//             v.push(format!("\t{}\n", cnt.borrow().desc()));
//             mem += cnt.borrow().memory_usage() as f32;
//         }
//
//         info!(
//             "\n{}{}",
//             format!(
//                 "stats: {} connections, {}k mem",
//                 self.conns.len(),
//                 mem / 1024.0
//             ),
//             &v.concat()
//         );
//     }
//
//     pub fn serve(&mut self) -> Result<()> {
//         let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.config.local_port);
//         let listener = TcpListener::bind(&addr).unwrap();
//         info!("Listening on: {}", addr);
//
//         let listener_token = Token(
//             self.conns
//                 .insert(new_rc_cell(Connection::new(false, self.config.clone())).clone()),
//         );
//         debug_assert_eq!(listener_token, LISTENER);
//
//         self.poll
//             .register(&listener, LISTENER, Ready::readable(), PollOpt::edge())?;
//
//         let mut now = time::SystemTime::now();
//         let mut evs = Events::with_capacity(64);
//         loop {
//             self.poll
//                 .poll(&mut evs, Some(time::Duration::from_millis(500)))?;
//
//             if now.elapsed().unwrap() > time::Duration::from_secs(20) {
//                 self.stats();
//                 now = time::SystemTime::now();
//             }
//
//             for ev in &evs {
//                 match ev.token() {
//                     LISTENER => {
//                         self.accept(&listener)?;
//                     }
//
//                     token @ _ => {
//                         if self.conns.contains(token.0) {
//                             let cnt = self.conns.get(token.0).unwrap();
//                             let rlt = cnt.borrow_mut().handle_events(&self.poll, &ev);
//                             if let Err(e) = rlt {
//                                 self.close_connection(e.0, e.1, &cnt.clone());
//                             }
//                         }
//                     }
//                 }
//             }
//         }
//     }
//
//     fn accept(&mut self, lis: &TcpListener) -> Result<()> {
//         loop {
//             match lis.accept() {
//                 Ok((stream, addr)) => {
//                     debug!("accpet connection {}.", addr);
//
//                     // self.create_local_connection(stream)?;
//                 }
//
//                 Err(e) => {
//                     if conn::is_wouldblock(&e) {
//                         return Ok(());
//                     } else {
//                         return Err(e);
//                     }
//                 }
//             }
//         }
//     }
//
//     pub fn create_local_connection(&mut self, handle: TcpStream) -> Result<()> {
//         let cnt = new_rc_cell(Connection::new(true, self.config.clone()));
//         let local_token = Token(self.conns.insert(cnt.clone()));
//         let rls = cnt.borrow_mut().register(
//             &mut self.poll,
//             handle,
//             local_token,
//             Ready::readable(),
//             PollOpt::edge(),
//             LOCAL,
//         );
//
//         match rls {
//             Err(e) => {
//                 self.conns.remove(local_token.0);
//
//                 Err(e)
//             }
//
//             Ok(_) => {
//                 let remote_token = Token(self.conns.insert(cnt.clone()));
//                 cnt.borrow_mut().set_token(remote_token, REMOTE);
//
//                 Ok(())
//             }
//         }
//     }
//
//     fn close_connection(
//         &mut self,
//         local_shut: Shutflag,
//         remote_shut: Shutflag,
//         cnt: &RcCell<Connection>,
//     ) {
//         debug!(
//             "close connection Shutflag({:?}, {:?}), @{}",
//             local_shut,
//             remote_shut,
//             cnt.borrow()
//         );
//         cnt.borrow_mut().shutdown(&self.poll, local_shut, LOCAL);
//         cnt.borrow_mut().shutdown(&self.poll, remote_shut, REMOTE);
//
//         let mut shut = cnt.borrow().get_shutflag(LOCAL);
//         if shut == Shutflag::both() {
//             debug!("  remove LOCAL end, {}", cnt.borrow().host());
//             let index = cnt.borrow().get_token(LOCAL).0;
//             if self.conns.contains(index) {
//                 self.conns.remove(index);
//                 cnt.borrow_mut().set_token(Token(std::usize::MAX), LOCAL);
//             }
//         }
//
//         shut = cnt.borrow().get_shutflag(REMOTE);
//         if shut == Shutflag::both() {
//             debug!("  remove REMOTE end, {}", cnt.borrow().host());
//             let index = cnt.borrow().get_token(REMOTE).0;
//             if self.conns.contains(index) {
//                 self.conns.remove(index);
//                 cnt.borrow_mut().set_token(Token(std::usize::MAX), REMOTE);
//             }
//         }
//     }
// }
