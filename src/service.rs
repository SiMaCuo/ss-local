use super::conn::*;
use super::rccell::*;
use log::info;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Poll, PollOpt, Ready, Token};
use slab::*;
use std::io::{ErrorKind::*, Result};
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
        let mut evs = Events::with_capacity(1024);
        loop {
            self.poll.poll(&mut evs, Some(timeout))?;

            let mut v: Vec<RcCell<Connection>> = Vec::with_capacity(128);
            for ev in &evs {
                match ev.token() {
                    LISTENER => {
                        self.accept(&listener)?;
                    }

                    token @ _ => {
                        let c = self.conns.get(token.0).unwrap();
                        if let Err(e) = c.borrow_mut().handle_events(&self.poll, &ev) {
                            info!("connection closed by {}", e);

                            v.push(c.clone());
                        }
                    }
                }
            }

            for c in v {
                self.close_connection(&c);
            }
        }
    }

    fn accept(&mut self, lis: &TcpListener) -> Result<()> {
        loop {
            match lis.accept() {
                Ok((stream, addr)) => {
                    info!("{:?} connected.", addr);

                    self.create_local_connection(stream)?;
                }

                Err(e) => {
                    if e.kind() == WouldBlock || e.kind() == Interrupted {
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
        let mut token = Token(self.conns.insert(cnt.clone()));
        self.poll
            .register(&handle, token, Ready::readable(), PollOpt::edge())
            .and_then(|_| {
                cnt.borrow_mut().set_stream(handle, LOCAL);
                cnt.borrow_mut().set_token(token, LOCAL);
                cnt.borrow_mut().set_interest(Ready::readable(), LOCAL);

                token = Token(self.conns.insert(cnt.clone()));
                cnt.borrow_mut().set_token(token, REMOTE);

                Ok(())
            })
    }

    fn close_connection(&mut self, cnt: &RcCell<Connection>) {
        cnt.borrow_mut().shutdown(&self.poll);

        self.conns.remove(cnt.borrow().get_token(LOCAL).0);
        cnt.borrow_mut().set_token(Token(std::usize::MAX), LOCAL);
        self.conns.remove(cnt.borrow().get_token(REMOTE).0);
        cnt.borrow_mut().set_token(Token(std::usize::MAX), REMOTE);
    }
}
