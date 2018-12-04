use super::conn::*;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Poll, PollOpt, Ready, Token};
use slab::*;
use std::io::{ErrorKind::*, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time;
#[macro_use]
use log::*;

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
                        let c = self.conns.get_mut(token.0).unwrap();
                        c.handle_events(&ev);
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
        let entry = self.conns.vacant_entry();
        let token = Token(entry.key());

        self.poll
            .register(&handle, token, Ready::readable(), PollOpt::edge())
            .and_then(|_| {
                let cnt = Connection::new(handle, token, Ready::readable());
                entry.insert(cnt);

                Ok(())
            })
    }

    pub fn register_connection(
        &self,
        cnt: &mut Connection,
        interest: Ready,
        is_local_stream: bool,
    ) -> Result<()> {
        let stream = cnt.get_stream(is_local_stream);
        let token = cnt.get_token(is_local_stream);

        self.poll
            .register(stream, token, interest, PollOpt::edge())
            .and_then(|_| {
                cnt.set_interest(interest, is_local_stream);

                Ok(())
            })
    }

    pub fn reregister_connection(
        &self,
        cnt: &mut Connection,
        interest: Ready,
        is_local_stream: bool,
    ) -> Result<()> {
        if cnt.get_interest(is_local_stream) != interest {
            self.poll
                .reregister(
                    cnt.get_stream(is_local_stream),
                    cnt.get_token(is_local_stream),
                    interest,
                    PollOpt::edge(),
                ).and_then(|_| {
                    cnt.set_interest(interest, is_local_stream);
                    Ok(())
                });
        }

        Ok(())
    }

    fn close_connection(&self, cnt: &mut Connection) -> Result<()> {
        cnt.shutdown(&self.poll);

        self.conns.remove(cnt.get_token(LOCAL).0);
        cnt.set_token(Token(std::usize::MAX), LOCAL);
        self.conns.remove(cnt.get_token(REMOTE).0);
        cnt.set_token(Token(std::usize::MAX), REMOTE);

        Ok(())
    }
}
