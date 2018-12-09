use super::conn::*;
use log::info;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Poll, PollOpt, Ready, Token};
use slab::*;
use std::io::{ErrorKind::*, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time;

const LISTENER: Token = Token(usize::max_value() - 1);

pub struct Service {
    conns: Slab<Connection>,
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
        println!("Listening on: {}", addr);

        self.poll
            .register(&listener, LISTENER, Ready::readable(), PollOpt::edge())?;

        let timeout = time::Duration::from_millis(500);
        let mut evs = Events::with_capacity(1024);
        loop {
            self.poll.poll(&mut evs, Some(timeout))?;

            for ev in &evs {
                match ev.token() {
                    LISTENER => {
                        self.accept(&listener);
                    }

                    token @ _ => {
                        let entry = self.conns.vacant_entry();
                        let c = self.conns.get_mut(token.0).unwrap();
                        c.handle_events(&self.poll, &entry, &ev);
                    }
                }
            }
        }
    }

    fn accept(&mut self, lis: &TcpListener) -> Result<()> {
        loop {
            match lis.accept() {
                Ok((stream, addr)) => {
                    info!("{:?} connected.", addr);

                    self.create_local_connection(stream);
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
        let entry_local = self.conns.vacant_entry();
        let entry_remote = self.conns.vacant_entry();
        let token_local = Token(entry_local.key());
        let token_remote = Token(entry_remote.key());

        self.poll
            .register(&handle, token_local, Ready::readable(), PollOpt::edge())
            .and_then(|_| {
                let cnt = Connection::new(handle, token_local, Ready::readable());
                entry_local.insert(cnt.clone());
                entry_remote.insert(cnt.clone());

                Ok(())
            })
    }

    fn close_connection(&mut self, cnt: &mut Connection) -> Result<()> {
        cnt.shutdown(&self.poll);

        self.conns.remove(cnt.get_token(LOCAL).0);
        cnt.set_token(Token(std::usize::MAX), LOCAL);
        self.conns.remove(cnt.get_token(REMOTE).0);
        cnt.set_token(Token(std::usize::MAX), REMOTE);

        Ok(())
    }
}
