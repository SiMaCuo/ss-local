extern crate tokio;
extern crate bytes;
extern crate futures;

use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use std::io;
use std::vec;
use Socks5::Socks5Phase;

struct Transfer {
    local: TcpStream,
    remote: TcpStream,
    buf: Vec<u8>,
    phase: Socks5Phase,
}

impl Transfer {
    fn new(local: TcpStream) -> Self {
        Transfer {
            local,
            buf: Vec::with_capacity(2048),
            phase: Socks5Phase::Initialize,
        }
    }
}

impl Future for Transfer {
    type Item = ();
    type Error = io:Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error>
        match phase {
            Socks5Phase::Initlize {
                let ready = self.local.poll_read_ready()?;
                if ready.is_not_ready(self) {
                    return Ok(Async::NotReady);
                }
                

