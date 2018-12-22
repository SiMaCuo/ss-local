use super::conn::{self, *};
use super::rccell::*;
use log::{debug, info};
use mio::{net::TcpListener, net::TcpStream, Events, Poll, PollOpt, Ready, Token};
use slab::*;
use std::io::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time;

const LISTENER: Token = Token(0);

pub struct Service {
    conns: Slab<RcCell<Connection>>,
    poll: Poll,
}

impl Service {
    pub fn new() -> Self {
        Service {
            conns: Slab::with_capacity(1024),
            poll: Poll::new().unwrap(),
        }
    }

    pub fn serve(&mut self) -> Result<()> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 18109);
        let listener = TcpListener::bind(&addr).unwrap();
        info!("Listening on: {}", addr);

        let listener_token = Token(self.conns.insert(new_rc_cell(Connection::new()).clone()));
        assert_eq!(listener_token, LISTENER);

        self.poll
            .register(&listener, LISTENER, Ready::readable(), PollOpt::edge())?;

        let timeout = time::Duration::from_millis(500);
        let mut evs = Events::with_capacity(64);
        let mut v: Vec<RcCell<Connection>> = Vec::with_capacity(128);
        loop {
            self.poll.poll(&mut evs, Some(timeout))?;

            for ev in &evs {
                match ev.token() {
                    LISTENER => {
                        self.accept(&listener)?;
                    }

                    token @ _ => {
                        let cnt = self.conns.get(token.0).unwrap();
                        let rlt = cnt.borrow_mut().handle_events(&self.poll, &ev);
                        if let Err(e) = rlt {
                            info!("close,   host {}, err {}", cnt.borrow().host(), e);

                            v.push(cnt.clone());
                        }
                    }
                }
            }

            for c in &v {
                self.close_connection(c);
            }

            v.clear();
        }
    }

    fn accept(&mut self, lis: &TcpListener) -> Result<()> {
        loop {
            match lis.accept() {
                Ok((stream, addr)) => {
                    debug!("accpet connection {}.", addr);

                    self.create_local_connection(stream)?;
                }

                Err(e) => {
                    if conn::is_wouldblock(&e) {
                        return Ok(());
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    pub fn create_local_connection(&mut self, handle: TcpStream) -> Result<()> {
        let cnt = new_rc_cell(Connection::new());
        let local_token = Token(self.conns.insert(cnt.clone()));
        let rls = cnt.borrow_mut().register(
            &mut self.poll,
            handle,
            local_token,
            Ready::readable(),
            PollOpt::edge(),
            LOCAL,
        );

        match rls {
            Err(e) => {
                self.conns.remove(local_token.0);

                Err(e)
            }

            Ok(_) => {
                let remote_token = Token(self.conns.insert(cnt.clone()));
                cnt.borrow_mut().set_token(remote_token, REMOTE);

                Ok(())
            }
        }
    }

    fn close_connection(&mut self, cnt: &RcCell<Connection>) {
        cnt.borrow_mut().shutdown(&self.poll);

        let mut index = cnt.borrow().get_token(LOCAL).0;
        if self.conns.contains(index) {
            self.conns.remove(index);
            cnt.borrow_mut().set_token(Token(std::usize::MAX), LOCAL);
        }

        index = cnt.borrow().get_token(REMOTE).0;
        if self.conns.contains(index) {
            self.conns.remove(index);
            cnt.borrow_mut().set_token(Token(std::usize::MAX), REMOTE);
        }
    }
}
