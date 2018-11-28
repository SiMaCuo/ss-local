use conn::*;
use mio::net::TcpListener;
use mio::{Events, Poll, PollOpt, Ready, Token};
use slab::*;
use std::io::{ErrorKind::*, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time;

const LISTENER: Token = Token(usize::max_value() - 1);

pub struct Service {
    conns: Slab<Connection>,
    p: Poll,
    evs: Events,
}

impl Service {
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

        self.poll
            .regisert(&listener, LISTENER, Ready::readable(), PollOpt::edge())?;

        let timeout = time::Duration::from_millis(500);
        loop {
            self.p.poll(&mut self.evs, Some(timeout))?;

            for ev in &self.evs {
                match ev.token() {
                    LISTENER => {
                        self.accept();
                    }

                    _ => {
                        let token = ev.token();
                        let c = self.conns.get_mut(token).unwrap();
                        c.handle_events(self.p, ev, token);
                    }
                }
            }
        }

        Ok(())
    }

    fn accept(&mut self, lis: &TcpListener) -> Result<()> {
        loop {
            match lis.accept() {
                Ok((stream, addr)) => {
                    println!("{:?} connected.", addr);

                    let entry = self.conns.vacant_entry();
                    let token = entry.key();
                    let c = Connection::new(stream, token, Ready::readable());
                    c.register(&mut self.p, LOCAL).unwrap();
                    entry.insert(token, c);
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

    fn close(&self, local_token: Token) -> Result<()> {
        let c = match self.conns.get(local_token) {
            Some(c) => c,
            None => {
                warn!("BUG->connection not find when try to close.");
                return Ok(());
            }
        };
        assert_eq!(local_token, c.get_token(LOCAL));

        c.close();
        self.conns.remove(c.get_token(REMOTE));
        self.conns.remove(c.get_token(LOCAL));

        Ok(())
    }

    fn handle_events(&mut self, ev: &mio::Event) -> Result<()> {
        let token = ev.token();
        let c = self.conns.get_mut(token).unwrap();
        if token == c.local_token {
            c.handle_local_events(ev);
        } else if token == c.remote_token.unwrap() {
            c.handle_remote_events(ev);
        } else {
            unreachable!();
        }
    }
}
