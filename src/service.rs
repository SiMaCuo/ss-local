use conn::*;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Poll, PollOpt, Ready, Token};
use slab::*;
use std::io::{self, Error, ErrorKind::*, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{mem, time};

const LISTENER: Token = Token(0);

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

        let lis_stream: TcpStream = unsafe { mem::uninitialized() };
        let c = Connection::new(lis_stream, LISTENER);
        assert_eq!(LISTENER, self.conns.insert(c));
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

                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn accept(&mut self, lis: &TcpListener) -> Result<()> {
        loop {
            match lis.accept() {
                (sock, addr) => {
                    println!("{:?} connected.", addr);

                    let entry = self.conns.vacant_entry();
                    let token = entry.key();
                    let c = Connection::new(sock, token);
                    c.register(&mut self.p, token, Ready::readable(), LOCAL, REGISTER)
                        .unwrap();
                    entry.insert(token, c);
                }

                Err(ref e) if e.kind() == WouldBlock => Ok(()),
                Err(e) => Err(e),
            }
        }

        Ok(())
    }

    fn handle_event(&mut self, ev: &mio::Event) -> Result<()> {
        let token = ev.token();
        let c = self.conns.get(token).unwrap();
        if token == c.local_token {
        } else if token == c.remote_token.unwrap() {
        } else {
            unreachable!();
        }
    }
}
