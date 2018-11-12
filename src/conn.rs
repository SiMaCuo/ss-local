use mio::{self, Ready, Token, Poll, PollOpt};
use mio::net::TcpStream;
use std::{cmp, mem, slice, ptr, net};
use std::io::{self, Read, Write, Error, ErrorKind};
use super::socks5::*;


const BUF_ALLOC_SIZE: usize = 4096;
const MIN_VACANT_SIZE:  usize = 512;
const LOCAL: bool     = true;
const REMOTE: bool    = false;

struct StreamBuf {
    buf: Vec<u8>,
    pos: usize,
}

impl StreamBuf {
    pub fn new() -> StreamBuf {
        StreamBuf {
            buf: Vec::with_capacity(BUF_ALLOC_SIZE),
            pos: 0,
        }
    }

    pub fn payload_len(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn tail_vacant_len(&self) -> usize {
        self.buf.capacity() - self.buf.len()
    }

    fn head_vacant_len(&self) -> usize {
        self.pos
    }

    fn vacant_len(&self) -> usize {
        self.tail_vacant_len() + self.head_vacant_len()
    }

    fn move_payload(&mut self) {
        assert!(self.pos <= self.buf.len());

        if self.pos == 0 || self.buf.len() == 0 {
            return;
        }

        if self.payload_len() == 0 {
            self.pos = 0;
            unsafe { self.buf.set_len(0); }

            return;
        }

        let len = self.payload_len();
        let src = self.buf.as_ptr().add(self.pos);
        let dst = self.buf.as_mut_ptr();
        unsafe {
            if len < self.pos {
                ptr::copy_nonoverlapping(src, dst, len);
            } else {
                ptr::copy(src, dst, len);
            }
            self.buf.set_len(len);
        }
        self.pos = 0;
    }

    pub fn write_to<W: Write>(&mut self, w: &mut W) -> io::Result<usize> {
        if self.payload_len() == 0 {
            return Err(Error::new(ErrorKind::WriteZero, "data buffer is empty."));
        }

        let result = w.write(&self.buf[self.pos..self.buf.len()]);
        match result {
            Ok(n) if n != 0 => {
                self.pos += n;
                if self.payload_len() == 0 {
                    self.pos = 0;
                    unsafe { self.buf.set_len(0); }
                }

                Ok(n)
            }

            Ok(_) => {
                Err(Error::new(ErrorKind::WriteZero, "can't write to target."))
            }

            Err(e) => result
        }
    }

    pub fn read_from<R: Read>(&mut self, r: &mut R) -> io::Result<usize> {
        let total_read_len: usize = 0;
        loop {
            let mut vacant_len = self.vacant_len();
            if vacant_len < MIN_VACANT_SIZE {
                if self.vacant_len() > 0 {
                    self.move_payload();
                }

                self.buf.reserve(BUF_ALLOC_SIZE);
            }
            
            let result = r.read(&mut self.buf[self.buf.len()..self.buf.capacity()]);
            match result {
                Ok(n) if n > 0 => { total_read_len += n; }
                Ok(_)  => { Ok(total_read_len); }
                Err(e) => { result }
            }
        }
    }
}

impl Read for StreamBuf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = cmp::min(buf.len(), self.payload_len());

        let src = self.buf.as_ptr().add(self.pos);
        let dst = buf.as_mut_ptr();
        unsafe {
            ptr::copy_nonoverlapping(src, dst, len);
        }

        Ok(len)
    }
}

impl Write for StreamBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.vacant_len() {
            if self.vacant_len() > 0 {
                self.move_payload();
            }

            let mul = buf.len() % BUF_ALLOC_SIZE + 1;
            self.buf.reserve(mul * BUF_ALLOC_SIZE);
        } else if buf.len() > self.tail_vacant_len() {
            self.move_payload();
        }

        let dst = self.buf.as_mut_ptr().add(self.buf.len());
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), dst, buf.len());
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


pub struct Connection {
    local: TcpStream,
    local_token: Token,
    local_buf: StreamBuf,
    local_intrest: Ready,
    remote: Option<TcpStream>,
    remote_token: Option<Token>,
    remote_buf: StreamBuf,
    remote_intrest: Ready,
    stage: Stage,
}

impl Connection {
    pub fn new(local: TcpStream, local_token: Token) -> Self 
    {
        Connection {
            local,
            local_token,
            local_buf: StreamBuf::new(),
            local_intrest: Ready::empty(),
            remote: None,
            remote_token: None,
            remote_buf: StreamBuf::new(),
            remote_intrest: Ready::empty(),
            stage: Initialize,
        }
    }

    fn get_stream(&self, is_local_stream: bool) -> &TcpStream 
    {
        if is_local_stream {
            self.local
        } else {
            self.remote.unwrap()?
        }
    }

    pub fn register(&self, &mut poll: Poll, token: Token, ready: Ready, is_local_stream: bool, is_reregister: bool) -> Result<()>
    {
        let token = if is_local_stream {
            self.local_token
        } else {
            self.remote_token
        };

        let opt = mio::PollOpt::edge();
        let result = if is_reregister {
            poll.reregister(self.get_stream(is_local_stream), token, ready, opt)
        } else {
            poll.register(self.get_stream(is_local_stream, token, ready, opt))
        };

        result.map(|_| {
            println!("{} {} between ({:?} {:?}) <--> {:?}",
                if is_reregister { "RE-register" } else { "register" },
                if is_local_stream { "LOCAL" } else { "REMOTE" },
                self.local.peer_addr()?, self.local.local_addr()?,
                self.remote.unwrap().local_addr()?);
        })
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

impl Future for Connection {
    type Item = usize;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<usize, io::Error>
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

                if BUF_ALLOC_SIZE > self.buf.len() {
                    match self.local.read(&mut self.buf[self.buf.len()..BUF_ALLOC_SIZE]) {
                        Ok(n) => {
                            if n == 0 {
                                self.local.shutdown(net::Shutdown::Both);
                                return Ok(Async::Ready(self.amt));
                            }

                            self.amt += n;
                        }

                        Err(err) if err.kind() == ErrorKind::Interrupted => {
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
                for pos in 1..nmethods {
                    if unsafe { *self.buf.get_unchecked(1+pos)} == Method::NoAuthRequired as u8 {
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




                
                







                

