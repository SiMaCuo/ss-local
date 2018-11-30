use conn::*;
use mio::net::{TcpListener, TcpStream};
use mio::{Evented, Events, Poll, PollOpt, Ready, Token};
use slab::*;
use std::io::{ErrorKind::*, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time;

const LISTENER: Token = Token(usize::max_value() - 1);

pub struct Service<'a> {
    conns: Slab<Connection<'a>>,
    p: Poll,
    evs: Events,
}

impl<'a> Service<'a> {
    pub fn new() -> Self {
        Service {
            conns: Slab::with_capacity(1024),
            p: Poll::new().unwrap(),
            evs: Events::with_capacity(1024),
        }
    }

    pub fn serve(&mut self) -> Result<()> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 18109);
        let listener = TcpListener::bind(&addr).unwrap();
        println!("Listening on: {}", addr);

        self.p
            .register(&listener, LISTENER, Ready::readable(), PollOpt::edge())?;

        let timeout = time::Duration::from_millis(500);
        loop {
            self.p.poll(&mut self.evs, Some(timeout))?;

            for ev in self.evs {
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

        self.p
            .register(&handle, token, Ready::readable(), PollOpt::edge())
            .and_then(|_| {
                let cnt = Connection::new(self, handle, token, Ready::readable());

                Ok(())
            })
    }

    pub fn register_remote_connection(
        &mut self,
        handle: TcpStream,
        cnt: &mut Connection,
    ) -> Result<()> {
        let entry = self.conns.vacant_entry();
        let token = Token(entry.key());

        self.p
            .register(&handle, token, Ready::readable(), PollOpt::edge())
            .and_then(|_| {
                cnt.set_remote_stream(handle);
                cnt.set_interest(Ready::readable(), LOCAL);
                cnt.set_token(token, LOCAL);

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

        self.p
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
            self.p
                .reregister(
                    cnt.get_stream(is_local_stream),
                    cnt.get_token(is_local_stream),
                    interest,
                    PollOpt::edge(),
                ).and_then(|_| {
                    cnt.set_interest(interest, is_local_stream);
                });
        }

        Ok(())
    }

    pub fn deregister_connection(&self, cnt: &mut Connection, is_local_stream: bool) -> Result<()> {
        let stream = cnt.get_stream(is_local_stream);
        cnt.set_interest(Ready::empty(), is_local_stream);

        self.p.deregister(stream)
    }

    fn close_connection(&self, cnt: &mut Connection) -> Result<()> {
        cnt.shutdown();

        self.conns.remove(cnt.get_token(LOCAL).0);
        cnt.set_token(Token(std::usize::MAX), LOCAL);
        self.conns.remove(cnt.get_token(REMOTE).0);
        cnt.set_token(Token(std::usize::MAX), REMOTE);

        Ok(())
    }
}
