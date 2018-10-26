extern crate tokio;
extern crate bytes;
extern crate futures;
extern crate mio;
extern crate libc;

use tokio::net::{TcpListener, TcpStream};
use std::{io, vec, mem, slice, ptr, net};
use Socks5::Socks5Phase;
use mio::Ready;

const BUF_SIZE: u32 = 2048

struct Transfer {
    local: TcpStream,
    remote: TcpStream,
    buf: Vec<u8>,
    idx: usize,
    amt: u64,
    phase: mut Socks5Phase,
}

impl Transfer {
    pub fn new(local: TcpStream) -> Self {
        Transfer {
            local,
            buf: Vec::with_capacity(BUF_SIZE),
            idx: 0,
            amt: 0,
            phase: Socks5Phase::Initialize,
        }
    }

    fn local_handshake(&mut self) -> Result<Asnyc<Self::Item, Self::Error>
    {
        let buf_len = self.buf.len();
        if buf_len < mem::size_of::<Socks5::Request>() {
            return Ok(Asnyc::NotReady);
        }
        
        let ver = unsafe { self.buf.get_unchecked(0) }
        if ver != SOCKS5_VERSION {
            return Ok(Async::Ready(self.amt));
        }
        
        let resp = Socks5::Response::new();
        let cmd = unsafe { self.buf.get_unchecked(1) }
        if cmd != Socks5::Connect {
            resp.rep = Socks5::CmdNotSupported;
            let bytes: &[u8] = unsafe { slice::from_raw_parts(
                    (&resp as *const Socks5::Response) as *const u8,
                    mem::size_of::<Socks5::Response>())
            }
            self.local.write_all(bytes);

            return Ok(Asnyc::Ready(self.buf.amt));
        }

        let atyp: Socks5::AddrType = unsafe { 
            mem::transmute<u8, Socks5::AddrType>(self.buf.get_unchecked(3)) 
        }
        
        let request_len = mem::size_of::<Socks5::Request>();
        match atyp {
            Socks5::V4 => {
                let ptr = self.buf.as_ptr();
                let ip = net::Ipv4Addr::from( 
                    unsafe {
                        let raw: *const u32 = ptr.offset(request_len as isize) as *const u32;
                        mem::transmute_copy<u32, u32>(raw)
                    } );
                let u32_len = mem::sizeof::<u32>();
                let port: u16 = u16::from_be(
                    unsafe {
                        let raw: *const u16 = ptr.offset((request_len + u32_len) as isize)) as *const u16;
                        mem::transmute_copy<u16, u16>(raw)
                    } );
            }

            Socks::Domain => {
                let name_len = unsafe { self.buf.get_unchecked(request_len) }
                
            }

            Socks5::V6 => {
            }
        }

        
}

impl Future for Transfer {
    type Item = ();
    type Error = io:Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error>
    {
        match phase {
            Socks5Phase::Initlize => {
                let read_ready: Async<Ready> = self.local.poll_read_ready(Ready::readable())?
                if read_ready.is_not_ready() {
                    return Ok(Async::NotReady);
                }

                let write_ready: Async<Ready> = self.local.poll_write_ready()?;
                if write_ready.is_not_ready() {
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

                let nmethods = unsafe {self.buf.get_unchecked(1) }
                let method_len = nmethods + mem::size_of::<Socks5::MethodSelectRequest>() - 1;
                if self.buf.len() < method_len {
                    return Ok(Asnyc::NotReady);
                }

                let mut resp = Socks5::MethodSelectResponse::new();
                for idx in (1..nmethods) {
                    if unsafe {self.buf.get_unchecked(1+idx)} == Method::NoAuthRequired {
                        resp.method = Method::NoAuthRequired;
                        break;
                    }
                }

                if resp.method != Method::NoAuthRequired {
                    self.local.shutdown(ShutDown::Both);
                    reutrn Ok(Async::Ready(self.buf.amt));
                }
                
                let bytes: &[u8] = unsafe {
                    slice::from_raw_parts(
                        (&resp as *const Socks5::MethodSelectResponse) as *const u8,
                        mem::size_of::<Socks5::MethodSelectResponse>())
                }

                self.local.write_all(bytes);
                phase = Socks5::Handshake;
                if method_len < self.buf.len() {
                    unsafe {
                        ptr::copy(self.buf.as_mut_ptr(),  
                                  self.buf.as_ptr().offset(method_len as isize),
                                  self.buf.len() - method_len); 
                    }
                    self.buf.set_len(self.buf.len() - method_len);
                    
                    continue;
                }

                self.buf.truncate(0);
                
                Ok(Async::NotReady)
            }
            
            Socks5::Handshake => 
        }

    }
}




                
                







                

