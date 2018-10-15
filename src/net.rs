extern crate tokio;
extern crate bytes;
extern crate futures;
extern crate mio;

use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use std::io;
use std::vec;
use Socks5::Socks5Phase;
use mio::Ready;

struct Transfer {
    local: TcpStream,
    remote: TcpStream,
    buf: Vec<u8>,
    idx: usize,
    phase: Socks5Phase,
}

impl Transfer {
    fn new(local: TcpStream) -> Self {
        Transfer {
            local,
            buf: Vec::with_capacity(2048),
            idx: 0,
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
                let ready: Async<Ready> = self.local.poll_read_ready(Ready::readable())?
                if ready.is_not_ready(self) {
                    return Ok(Async::NotReady);
                }

                let len = self.buf.capacity() - self.buf.len();


                

