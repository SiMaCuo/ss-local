use super::err::*;
use super::socks5::*;
use mio::net::TcpStream;
use mio::{self, Event, Poll, PollOpt, Ready, Token};
use std::io::{self, Error, ErrorKind::*, Read, Write};
use std::{cmp, mem, net, ptr, slice};

const BUF_ALLOC_SIZE: usize = 4096;
const MIN_VACANT_SIZE: usize = 512;
pub const LOCAL: bool = true;
pub const REMOTE: bool = false;
pub const REREGISTER: bool = true;
pub const REGISTER: bool = false;

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

    pub fn read_u8(&mut self) -> Result<u8, err::CliError> {
        if self.payload_len() < 1 {
            return CliError::from(WouldBlock);
        }

        let mut b = [0u8; 1];
        self.read_exact(&mut b);

        Ok(b[0])
    }

    pub fn read_port(&mut self) -> Result<u16> {
        if self.payload_len() < 2 {
            return CliError::from(WouldBlock);
        }

        let mut b = [0u8; 2];
        self.read_exact(&mut b)?;
        let mut port: u16 = 0;
        unsafe {
            ptr::copy_nonoverlapping(b.as_ptr(), &mut port as *mut u16 as *mut u8, 2);
        }

        Ok(port)
    }

    pub fn read_addr(&mut self) -> Result<String> {
        Ok("xyz".to_string())
    }

    pub fn peek(&self, size: usize) -> Result<&[u8]> {
        if size > self.payload_len() {
            return CliError::from(WouldBlock);
        }

        Ok(&self.buf[self.pos..self.pos + size])
    }

    pub fn consume(&mut self, size: usize) -> Result<usize> {
        let n = cmp::min(self.payload_len(), size);
        self.pos += n;
        if self.pos == self.buf.len() {
            self.pos = 0;
            unsafe {
                self.buf.set_len(0);
            }
        }

        Ok(n)
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
            unsafe {
                self.buf.set_len(0);
            }

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

    pub fn write_buf_to<W: Write>(&mut self, w: &mut W, buf: &[u8]) -> io::Result<usize, CliError> {
        if self.payload_len() > 0 {
            let n = self.write(buf).unwrap();
            assert_eq!(n == buf.len());

            self.write_to(w)
        } else {
            match w.write(buf) {
                Err(ref e) if e != WouldBlock || e != Interrupted => CliErr::from(e),
                _ => {
                    self.write(buf);
                    CliError::from(WouldBlock)
                }
            }
        }
    }

    pub fn write_to<W: Write>(&mut self, w: &mut W) -> io::Result<usize, CliError> {
        let result = w.write(&self.buf[self.pos..self.buf.len()]);
        match result {
            Ok(n) if n != 0 => {
                self.pos += n;
                if self.payload_len() == 0 {
                    self.pos = 0;
                    unsafe {
                        self.buf.set_len(0);
                    }
                }

                Ok(n)
            }

            Ok(_) => CliError::from(WouldBlock),

            Err(e) => CliError::from(e),
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
                Ok(n) if n > 0 => total_read_len += n,

                Ok(_) => {
                    if total_read_len == 0 {
                        return CliError::from(UnexpectedEof);
                    } else {
                        return Ok(total_read_len);
                    }
                }

                Err(e) if e == WouldBlock || e == Interrupted => return Ok(total_read_len),

                Err(e) => return result,
            }
        }
    }
}

impl Read for StreamBuf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = Read::read(
            &mut self.buf[self.head_vacant_len()..self.tail_vacant_len()],
            buf,
        )?;
        self.pos += len;
        if self.pos == self.buf.len() {
            self.pos = 0;
            unsafe {
                self.buf.set_len(0);
            };
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

        let len = Write::write(&mut self.buf[self.buf.len()..self.buf.capacity()], buf)?;
        unsafe {
            self.buf.set_len(self.buf.len() + len);
        };

        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Connection {
    local: TcpStream,
    local_token: Token,
    local_buf: StreamBuf,
    local_interest: Ready,
    remote: Option<TcpStream>,
    remote_token: Token,
    remote_buf: StreamBuf,
    remote_interest: Ready,
    stage: Stage,
}

impl Connection {
    pub fn new(local: TcpStream, local_token: Token, interest: Ready) -> Self {
        Connection {
            local,
            local_token,
            local_buf: StreamBuf::new(),
            local_interest: interest,
            remote: None,
            remote_token: Token::from(usize::max_value()),
            remote_buf: StreamBuf::new(),
            remote_interest: Ready::empty(),
            stage: Stage::Initialize,
        }
    }

    fn get_stream(&self, is_local_stream: bool) -> &TcpStream {
        if is_local_stream {
            &self.local
        } else {
            &self.remote.unwrap()
        }
    }

    fn get_buf(&self, is_local_stream: bool) -> &StreamBuf {
        if is_local_stream {
            &self.local_buf
        } else {
            &self.remote_buf
        }
    }

    fn get_buf_mut(&mut self, is_local_stream: bool) -> &mut StreamBuf {
        if is_local_stream {
            &mut self.local_buf
        } else {
            &mut self.remote_buf
        }
    }

    fn get_token(&self, is_local_stream: bool) -> Token {
        if is_local_stream {
            self.local_token
        } else {
            self.remote_token
        }
    }

    fn get_interest(&self, is_local_stream: bool) -> Ready {
        if is_local_stream {
            self.local_interest
        } else {
            self.remote_interest
        }
    }

    fn set_interest(&mut self, poll: &mut Poll, interest: Ready, is_local_stream: bool) {
        let current = if is_local_stream {
            self.local_interest
        } else {
            self.remote_interest
        };

        if current == interest {
            return;
        }

        let result = poll.reregister(
            self.get_stream(is_local_stream),
            self.get_token(is_local_stream),
            interest,
            mio::PollOpt::edge(),
        );

        if result.is_ok() {
            if is_local_stream {
                self.local_interest = interest;
            } else {
                self.remote_interest = interest;
            }
        }

        result.map(|_| {
            println!(
                "RE-register {} between ({:?} {:?}) <--> {:?}",
                if is_local_stream { "LOCAL" } else { "REMOTE" },
                self.local.peer_addr()?,
                self.local.local_addr()?,
                if let Some(ref remote) = self.remote {
                    remote.local_addr()?
                } else {
                    "*"
                }
            );
        })
    }

    pub fn register(&self, poll: &mut Poll, is_local_stream: bool) -> io::Result<()> {
        let result = poll.register(
            self.get_stream(is_local_stream),
            self.get_token(is_local_stream),
            self.get_interest(is_local_stream),
            mio::PollOpt::edge(),
        );

        result.map(|_| {
            println!(
                "register {} between ({:?} {:?}) <--> {:?}",
                if is_local_stream { "LOCAL" } else { "REMOTE" },
                self.local.peer_addr()?,
                self.local.local_addr()?,
                if let Some(ref remote) = self.remote {
                    remote.local_addr()?
                } else {
                    "*"
                }
            );
        })
    }

    fn handle_local_auth_method(&mut self, ev: &Event) -> io::Result<(), err::CliError> {
        assert!(ev.is_readable());

        let stream = self.get_stream(LOCAL);
        let buf = self.get_buf_mut(LOCAL);
        buf.read_from(stream)?;
        if buf.payload_len() < METHOD_SELECT_HEAD_LEN {
            println!(
                "auth {}, recive data less than  {} bytes.",
                stream.peer_addr()?,
                METHOD_SELECT_HEAD_LEN
            );

            return Ok(());
        }

        let head = buf.peek(METHOD_SELECT_HEAD_LEN);
        if head[0] != SOCKS5_VERSION {
            return Error::from(InvalidData);
        }

        let nmethods = head[1];
        let method_sel_len = nmethods + METHOD_SELECT_HEAD_LEN;
        if method_sel_len > self.payload_len() {
            println!(
                "auth {}, recive data size {} less than need {}.",
                stream.peer_addr()?,
                self.payload_len(),
                method_sel_len
            );

            return Ok(());
        }

        let mut method = Method::NO_ACCEPT_METHOD;
        let sel = buf.peek(method_sel_len);
        for pos in 0..nmethods {
            if sel[METHOD_SELECT_HEAD_LEN + pos] == Method::NO_AUTH {
                method = Method::NO_AUTH;
                break;
            }
        }

        buf.consume(method_sel_len);

        if method != Method::NO_AUTH {
            println!("auth {}, need auth method.", stream.peer_addr()?);

            return CliError::from(NO_ACCEPT_METHOD);
        }
    }

    fn local_handshake(&mut self) -> Result<usize> {
        let buf_len = self.buf.len();
        if buf_len < mem::size_of::<Request>() {
            return Err(Error::from(WouldBlock));
        }

        let ver = unsafe { *self.buf.get_unchecked(0) };
        if ver != SOCKS5_VERSION {
            return Err(Error::from(InvalidInput));
        }

        let mut resp = Response::new();
        let cmd = unsafe { *self.buf.get_unchecked(1) };
        if cmd != Command::Connect as u8 {
            resp.rep = Reply::CmdNotSupported as u8;
            let bytes: &[u8] = unsafe {
                slice::from_raw_parts(
                    (&resp as *const Response) as *const u8,
                    mem::size_of::<Response>(),
                )
            };
            self.local.write_all(bytes);

            return Err(Error::from(InvalidInput));
        }

        let atyp: AddrType =
            unsafe { mem::transmute_copy::<u8, AddrType>(self.buf.get_unchecked(2)) };

        let request_len = mem::size_of::<Request>();
        match atyp {
            V4 => {
                if self.buf.len() - request_len
                    < mem::size_of::<net::Ipv4Addr>() + mem::size_of::<u16>()
                {
                    return Err(Error::from(WouldBlock));
                }

                let ptr = self.buf.as_ptr();
                let ip = net::Ipv4Addr::from(unsafe {
                    let raw: *const u32 = ptr.offset(request_len as isize) as *const u32;
                    mem::transmute_copy::<u32, u32>(&*raw)
                });
                let u32_len = mem::size_of::<u32>();
                let port: u16 = u16::from_be(unsafe {
                    let raw: *const u16 =
                        ptr.offset((request_len + u32_len) as isize) as *const u16;
                    mem::transmute_copy::<u16, u16>(&*raw)
                });
            }

            Domain => {
                if self.buf.len() < request_len + 1 {
                    return Err(Error::from(WouldBlock));
                }

                let name_len = unsafe { *self.buf.get_unchecked(request_len) as usize };
                if self.buf.len() < request_len + name_len + 1 {
                    return Err(Error::from(WouldBlock));
                }

                let name_buf: Vec<u8> = Vec::with_capacity(name_len);
                unsafe {
                    let name_ptr = self.buf.as_ptr().offset((request_len + 1) as isize);
                    ptr::copy_nonoverlapping(name_ptr, name_buf.as_mut_ptr(), name_len);
                    name_buf.set_len(name_len);
                }

                let port: u16 = u16::from_be(unsafe {
                    let ptr = self.buf.as_ptr();
                    let raw: *const u16 =
                        ptr.offset((request_len + name_len + 1) as isize) as *const u16;
                    *raw
                });
            }

            V6 => {
                let addr6_len = mem::size_of::<net::Ipv6Addr>();
                let port_len = mem::size_of::<u16>();
                if self.buf.len() < request_len + addr6_len + port_len {
                    return Err(Error::from(WouldBlock));
                }

                let mut addr6_bytes: [u8; 16] = unsafe { mem::uninitialized() };
                addr6_bytes.copy_from_slice(&(&self.buf)[request_len..request_len + addr6_len]);
                let ip = net::Ipv6Addr::from(addr6_bytes);
                let port: u16 = u16::from_be(unsafe {
                    let ptr = self.buf.as_ptr();
                    let raw = ptr.offset((request_len + addr6_len) as isize) as *const u16;
                    *raw
                });
            }
        }

        Err(Error::from(WouldBlock))
    }
}

impl Future for Connection {
    type Item = usize;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<usize, io::Error> {
        match self.phase {
            Stage::Initialize => {
                let read_ready: Async<Ready> = self.local.poll_read_ready(Ready::readable())?;
                if read_ready.is_not_ready() {
                    return Err(Error::from(WouldBlock));
                }

                let write_ready: Async<Ready> = self.local.poll_write_ready()?;
                if write_ready.is_not_ready() {
                    return Err(Error::from(WouldBlock));
                }

                if BUF_ALLOC_SIZE > self.buf.len() {
                    match self
                        .local
                        .read(&mut self.buf[self.buf.len()..BUF_ALLOC_SIZE])
                    {
                        Ok(n) => {
                            if n == 0 {
                                self.local.shutdown(net::Shutdown::Both);
                                return Ok(Async::Ready(self.amt));
                            }

                            self.amt += n;
                        }

                        Err(err) if err.kind() == Interrupted => {
                            return Err(Error::from(WouldBlock));
                        }

                        _ => {
                            self.local.shutdown(net::Shutdown::Both);
                            return Ok(Async::Ready(self.amt));
                        }
                    }
                }

                if self.buf.len() < mem::size_of::<MethodSelectRequest>() {
                    return Err(Error::from(WouldBlock));
                }

                if *self.buf.get_unchecked(0) != SOCKS5_VERSION {
                    self.local.shutdown(net::Shutdown::Both);
                    return Ok(Async::Ready(self.amt));
                }

                let nmethods = unsafe { *self.buf.get_unchecked(1) as usize };
                let method_len = nmethods + mem::size_of::<MethodSelectRequest>() - 1;
                if self.buf.len() < method_len {
                    return Err(Error::from(WouldBlock));
                }

                let mut resp = MethodSelectResponse::new();
                for pos in 1..nmethods {
                    if unsafe { *self.buf.get_unchecked(1 + pos) } == Method::NoAuthRequired as u8 {
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
                        mem::size_of::<MethodSelectResponse>(),
                    )
                };

                self.local.write_all(bytes);
                self.phase = Stage::Handshake;
                if method_len < self.buf.len() {
                    unsafe {
                        ptr::copy(
                            self.buf.as_ptr().offset(method_len as isize),
                            self.buf.as_mut_ptr(),
                            self.buf.len() - method_len,
                        );
                    }
                    self.buf.set_len(self.buf.len() - method_len);

                    //continue;
                }

                self.buf.truncate(0);

                Err(Error::from(WouldBlock))
            }

            Handshake => self.local_handshake(),
        }
    }
}
