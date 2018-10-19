extern crate tokio;
extern crate bytes;
extern crate futures;
extern crate mio;

use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use std::{io, vec, mem};
use Socks5::Socks5Phase;
use mio::Ready;

const BUF_SIZE: u32 = 2048

struct Transfer {
    local: TcpStream,
    remote: TcpStream,
    buf: Vec<u8>,
    idx: usize,
    amt: u64,
    phase: Socks5Phase,
}

impl Transfer {
    fn new(local: TcpStream) -> Self {
        Transfer {
            local,
            buf: Vec::with_capacity(BUF_SIZE),
            idx: 0,
            amt: 0,
            phase: Socks5Phase::Initialize,
        }
    }
}

impl Future for Transfer {
    type Item = ();
    type Error = io:Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error>
        match phase {
            Socks5Phase::Initlize => {
                let ready: Async<Ready> = self.local.poll_read_ready(Ready::readable())?
                if ready.is_not_ready(self) {
                    return Ok(Async::NotReady);
                }

                if BUF_SIZE > self.buf.len() {
                    match local.read(&mut buf[self.buf.len()..BUF_SIZE]) {
                        Ok(n) => {
                            if n == 0 {
                                self.local.shutdown(ShutDown::Both);
                                return Ok(Async::Ready(self.buf.amt));
                            }

                            self.buf.amt += n as u64;
                        }
                        Err(err) if err == ErrorKind::Interrupted => return Ok(Async::NotReady);
                        _ => {
                            self.local.shutdown(ShutDown::Both);
                            return Ok(Async::Ready(self.buf.amt));
                        }
                    }
                }
                
                if self.buf.len() < mem::size_of::<Socks5::MethodSelectRequest>() {
                    return Ok(Asnyc::NotReady);
                }

                if self.buf.get_unchecked(0) != Socks5::SOCKS5_VERSION {
                    self.local.shutdown(ShutDown::Both);
                    return Ok(Async::Ready(self.buf.amt));
                }





                

