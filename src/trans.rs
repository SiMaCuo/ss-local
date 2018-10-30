use tokio::net::TcpStream;
use tokio::io::ErrorKind;
use tokio::prelude::*;
use mio::Ready;
use futures::future::Future;
use std::{io, mem, slice, ptr, net};
use super::socks5::*;

const BUF_SIZE: usize = 2048;

pub struct Transfer {
    local: TcpStream,
    remote: TcpStream,
    buf: Vec<u8>,
    idx: usize,
    amt: usize,
    phase: Socks5Phase,
}

impl Transfer {
    pub fn new(local: TcpStream) -> Self 
    {
        Transfer {
            local,
            remote: unsafe { mem::uninitialized() },
            buf: Vec::with_capacity(BUF_SIZE),
            idx: 0,
            amt: 0,
            phase: Socks5Phase::Initialize,
        }
    }

    fn local_handshake(&mut self) -> Result<Async<usize>, io::Error> 
    {
        let buf_len = self.buf.len();
        if buf_len < mem::size_of::<Request>() {
            return Ok(Async::NotReady);
        }
        
        let ver = unsafe { *self.buf.get_unchecked(0) };
        if ver != SOCKS5_VERSION {
            return Ok(Async::Ready(self.amt));
        }
        
        let mut resp = Response::new();
        let cmd = unsafe { *self.buf.get_unchecked(1) };
        if cmd != Command::Connect as u8 {
            resp.rep = Reply::CmdNotSupported as u8;
            let bytes: &[u8] = unsafe { slice::from_raw_parts(
                    (&resp as *const Response) as *const u8,
                    mem::size_of::<Response>())
            };
            self.local.write_all(bytes);

            return Ok(Async::Ready(self.amt));
        }

        let atyp: AddrType = unsafe { mem::transmute_copy::<u8, AddrType>(self.buf.get_unchecked(2)) };
        
        let request_len = mem::size_of::<Request>();
        match atyp {
            V4 => {
                if self.buf.len() - request_len < mem::size_of::<net::Ipv4Addr>() + mem::size_of::<u16>() {
                    return Ok(Async::NotReady);
                }

                let ptr = self.buf.as_ptr();
                let ip = net::Ipv4Addr::from( 
                    unsafe {
                        let raw: *const u32 = ptr.offset(request_len as isize) as *const u32;
                        mem::transmute_copy::<u32, u32>(&*raw)
                    } );
                let u32_len = mem::size_of::<u32>();
                let port: u16 = u16::from_be(
                    unsafe {
                        let raw: *const u16 = ptr.offset((request_len + u32_len) as isize) as *const u16;
                        mem::transmute_copy::<u16, u16>(&*raw) }
                );
            }

            Domain => {
                if self.buf.len() < request_len + 1 {
                    return Ok(Async::NotReady);
                }

                let name_len = unsafe { *self.buf.get_unchecked(request_len) as usize };
                if self.buf.len() < request_len + name_len + 1 {
                    return Ok(Async::NotReady);
                }

                let name_buf: Vec<u8> = Vec::with_capacity(name_len);
                unsafe {
                    let name_ptr = self.buf.as_ptr().offset((request_len + 1) as isize);
                    ptr::copy_nonoverlapping(name_ptr, name_buf.as_mut_ptr(), name_len);
                    name_buf.set_len(name_len);
                }
                
                let port: u16 = u16::from_be(
                    unsafe {
                        let ptr = self.buf.as_ptr();
                        let raw: *const u16 = ptr.offset((request_len+name_len+1) as isize) as *const u16;
                        *raw
                    } );
            }

            V6 => {
                let addr6_len = mem::size_of::<net::Ipv6Addr>();
                let port_len = mem::size_of::<u16>();
                if self.buf.len() < request_len + addr6_len + port_len {
                    return Ok(Async::NotReady);
                }
                
                let mut addr6_bytes: [u8; 16] = unsafe { mem::uninitialized() };
                addr6_bytes.copy_from_slice(&(&self.buf)[request_len..request_len+addr6_len]);
                let ip = net::Ipv6Addr::from(addr6_bytes);
                let port: u16 = u16::from_be(
                    unsafe {
                        let ptr = self.buf.as_ptr();
                        let raw = ptr.offset((request_len+addr6_len) as isize) as *const u16;
                        *raw
                    } );
            }
        }

        Ok(Async::NotReady)
    }
}

impl Future for Transfer {
    type Item = usize;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error>
    {
        match self.phase {
            Socks5Phase::Initialize => {
                let read_ready: Async<Ready> = self.local.poll_read_ready(Ready::readable())?;
                if read_ready.is_not_ready() {
                    return Ok(Async::NotReady);
                }

                let write_ready: Async<Ready> = self.local.poll_write_ready()?;
                if write_ready.is_not_ready() {
                    return Ok(Async::NotReady);
                }

                if BUF_SIZE > self.buf.len() {
                    match self.local.read(&mut self.buf[self.buf.len()..BUF_SIZE]) {
                        Ok(n) => {
                            if n == 0 {
                                self.local.shutdown(net::Shutdown::Both);
                                return Ok(Async::Ready(self.amt));
                            }

                            self.amt += n;
                        }

                        Err(err) if err == ErrorKind::Interrupted => {
                            return Ok(Async::NotReady);
                        }

                        _ => {
                            self.local.shutdown(net::Shutdown::Both);
                            return Ok(Async::Ready(self.amt));
                        }
                    }
                }
                
                if self.buf.len() < mem::size_of::<MethodSelectRequest>() {
                    return Ok(Async::NotReady);
                }
                
                if *self.buf.get_unchecked(0) != SOCKS5_VERSION {
                    self.local.shutdown(net::Shutdown::Both);
                    return Ok(Async::Ready(self.amt));
                }

                let nmethods = unsafe { *self.buf.get_unchecked(1) as usize };
                let method_len = nmethods + mem::size_of::<MethodSelectRequest>() - 1;
                if self.buf.len() < method_len {
                    return Ok(Async::NotReady);
                }

                let mut resp = MethodSelectResponse::new();
                for idx in 1..nmethods {
                    if unsafe { *self.buf.get_unchecked(1+idx)} == Method::NoAuthRequired as u8 {
                        resp.method = Method::NoAuthRequired as u8;
                        break;
                    }
                }

                if resp.method != Method::NoAuthRequired as u8 {
                    self.local.shutdown(net::Shutdown::Both);

                    return Ok(Async::Ready(self.amt));
                }
                
                let bytes: &[u8] = unsafe {
                    slice::from_raw_parts(
                        (&resp as *const MethodSelectResponse) as *const u8,
                        mem::size_of::<MethodSelectResponse>())
                };

                self.local.write_all(bytes);
                self.phase = Socks5Phase::Handshake;
                if method_len < self.buf.len() {
                    unsafe {
                        ptr::copy(self.buf.as_ptr().offset(method_len as isize),
                                  self.buf.as_mut_ptr(),
                                  self.buf.len() - method_len); 
                    }
                    self.buf.set_len(self.buf.len() - method_len);
                    
                    //continue;
                }

                self.buf.truncate(0);
                
                Ok(Async::NotReady)
            }
            
            Handshake => {
                self.local_handshake()
            }
        }

    }
}




                
                







                

