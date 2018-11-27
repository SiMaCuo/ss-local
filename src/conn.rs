use super::err::{CliError::*, *};
use super::socks5::{AddrType::*, Rep::*, Stage::*, *};
use mio::{self, net::TcpStream, Event, Poll, PollOpt, Ready, Token};
use std::io::{self, ErrorKind::*, Read, Write};
use std::{cmp, mem, net, ptr, str, fmt::Debug};

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

    pub fn read_u8(&mut self) -> Result<u8, CliError> {
        if self.payload_len() < 1 {
            return Err(CliError::from(WouldBlock));
        }

        let mut b = [0u8; 1];
        self.read_exact(&mut b);

        Ok(b[0])
    }

    pub fn read_port(&mut self) -> Result<u16, CliError> {
        if self.payload_len() < 2 {
            return Err(CliError::from(WouldBlock));
        }

        let mut b = [0u8; 2];
        self.read_exact(&mut b)?;
        let mut port: u16 = 0;
        unsafe {
            ptr::copy_nonoverlapping(b.as_ptr(), &mut port as *mut u16 as *mut u8, 2);
        }

        Ok(port)
    }

    pub fn read_addr(&mut self) -> Result<String, CliError> {
        Ok("xyz".to_string())
    }

    pub fn get_u8_unchecked(&self, index: usize) -> u8 {
        unsafe { self.buf.get_unchecked(index) }
    }

    pub fn peek(&self, size: usize) -> Result<&[u8], CliError> {
        if size > self.payload_len() {
            return Err(CliError::from(WouldBlock));
        }

        Ok(&self.buf[self.pos..self.pos + size])
    }

    pub fn consume(&mut self, size: usize) -> Result<usize, CliError> {
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

    pub fn write_buf_to<W: Write>(&mut self, buf: &[u8], w: &mut W) -> Result<usize, CliError> {
        if self.payload_len() > 0 {
            let n = self.write(buf).unwrap();
            assert_eq!(n, buf.len());

            self.write_to(w);
            if self.payload_len() > 0 {
                Err(CliError::from(WouldBlock))
            } else {
                Ok(n)
            }
        } else {
            match w.write(buf) {
                Err(e) => Err(CliError::from(e.kind())),

                Ok(n) => {
                    if n < buf.len() {
                        self.write(buf[n..]);
                    }
                    Err(CliError::from(WouldBlock))
                }
            }
        }
    }

    pub fn write_to<W: Write+Debug>(&mut self, w: &mut W) -> Result<usize, CliError> {
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

            Ok(_) => {
                info!("{:?} write to {:?} 0 bytes, maybe this connection is closed by peer.", self, w);
                
                Err(CliError::from(WouldBlock))
            },

            Err(e) => Err(CliError::from(e)),
        }
    }

    pub fn read_from<R: Read>(&mut self, r: &mut R) -> Result<usize, CliError> {
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
                        return Err(CliError::from(UnexpectedEof));
                    } else {
                        return Ok(total_read_len);
                    }
                }

                Err(e) if e.kind() == WouldBlock || e.kind() == Interrupted => {
                    if total_read_len > 0 {
                        return Ok(total_read_len);
                    } else {
                        return Err(CliError::from(WouldBlock));
                    }
                }

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

    fn set_interest(&mut self, poll: &Poll, interest: Ready, is_local_stream: bool) {
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
            PollOpt::edge(),
        );
        
        match result {
            Ok(()) => {
                if is_local_stream {
                    self.local_interest = interest;
                } else {
                    self.remote_interest = interest;
                }
            },

            Err(_) => {
                info!(
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
            },
        }


    }

    pub fn register(
        &self,
        poll: &mut Poll,
        token: Token,
        interest: mio::Ready,
        is_local_stream: bool,
    ) -> io::Result<()> {
        let result = poll.register(
            self.get_stream(is_local_stream),
            self.get_token(is_local_stream),
            self.get_interest(is_local_stream),
            PollOpt::edge(),
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

    pub fn close(&self, poll: &Poll) {
        self.get_stream(LOCAL).shutdown(net::Shutdown::Both);
        poll.deregister(self.get_stream(LOCAL));

        if self.remote.is_some() {
            self.get_stream(REMOTE).shutdown(net::Shutdown::Both);
            poll.deregister(self.get_stream(REMOTE));
        }
    }

    fn handle_local_events(&mut self, poll: &Poll, ev: &mio::Event) -> Result<(), CliError> {
        let stream = self.get_stream(LOCAL);
        let buf = self.get_buf_mut(LOCAL);
        if ev.is_readable() {
            buf.read_from(stream)?;
            match self.stage {
                LocalConnected => self.handle_local_auth_method(poll, ev),
            }
        } else if ev.is_writeable() {
            match self.stage {
                WaitSndMethodSelReply => self.handle_local_snd_methodsel_reply(poll, ev),
            }
        }

        Ok(())
    }

    fn handle_local_auth_method(&mut self, poll: &Poll, ev: &Event) -> Result<(), CliError> {
        let buf = self.get_buf(LOCAL);
        if buf.payload_len() < METHOD_SELECT_HEAD_LEN {
            println!(
                "auth {}, recive data less than  {} bytes.",
                self.local.peer_addr()?,
                METHOD_SELECT_HEAD_LEN
            );

            return Ok(());
        }

        let head = buf.peek(METHOD_SELECT_HEAD_LEN)?;
        let (ver, nmethods) = (head[0], head[1]);
        if ver != SOCKS5_VERSION {
            return Err(CliError::from(InvalidData));
        }

        let method_sel_len = nmethods + METHOD_SELECT_HEAD_LEN;
        if method_sel_len > buf.payload_len() {
            println!(
                "auth {}, recive data size {} less than need {}.",
                self.local.peer_addr()?,
                buf.payload_len(),
                method_sel_len
            );

            return Ok(());
        }

        let mut method = Method::NO_ACCEPT_METHOD;
        let sel = self.buf.peek(method_sel_len);
        for pos in 0..nmethods {
            if sel[METHOD_SELECT_HEAD_LEN + pos] == Method::NO_AUTH {
                method = Method::NO_AUTH;
                break;
            }
        }

        self.buf.consume(method_sel_len);

        if method != Method::NO_AUTH {
            return CliError::from(Method::NO_ACCEPT_METHOD);
        }

        let no_auth = [SOCKS5_VERSION; 2];
        no_auth[1] = Method::NO_AUTH;

        match self.write_buf_to(self.get_stream_mut(LOCAL), &no_auth) {
            StdIo(ref e) if e.kind() == WouldBlock => {
                self.set_interest(poll, Ready::writable(), LOCAL);
                self.stage = WaitSndMethodSelReply;
            }

            Ok(n) => Ok(()),

            e @ _ => e,
        }
    }

    fn handle_local_snd_methodsel_reply(
        &mut self,
        poll: &Poll,
        ev: mio::Event,
    ) -> Result<(), CliError> {
        let local_buf = self.get_buf_mut(LOCAL);
        assert!(local_buf.payload_len() > 0);

        if let StdIo(ref e) = local_buf.write_to(self.get_stream(LOCAL)) {
            if e != WouldBlock {
                return CliError::from(e);
            }
        }

        if local_buf.payload_len() == 0 {
            self.set_interest(poll, Ready::readable());
            self.stage = HandShake;
        }

        Ok(())
    }

    fn handle_handshake(&mut self, poll: &Poll, ev: &mio::Event) -> Result<(), CliError> {
        let local_buf = self.get_buf(LOCAL);
        let head = local_buf.peek(4)?;
        let (ver, cmd, rsv, atpy) = (head[0], head[1], head[2], head[3]);
        if ver != SOCKS5_VERSION {
            return CliError::from(Rep::GENERAL_FAILURE);
        }

        let addr: String = "0.0.0.0".to_string();
        let port: u16 = u16::max_value();
        match atpy {
            AddrType::V4 => {
                if local_buf.payload_len() < CMD_IPV4_LEN {
                    return Err(CliError::from(WouldBlock));
                }

                let bs = local_buf.peek(CMD_IPV4_LEN)?;
                addr = net::Ipv4Addr::new(
                    bs[CMD_HEAD_LEN],
                    bs[CMD_HEAD_LEN + 1],
                    bs[CMD_HEAD_LEN + 2],
                    bs[CMD_HEAD_LEN + 3],
                ).to_string();
                port = unsafe { mem::transmute::<[u8; 2], u16>([bs[8], bs[9]]).from_be() };

                local_buf.consume(CMD_IPV4_LEN);
            }

            AddrType::DOMAIN => {
                if local_buf.payload_len() < CMD_HEAD_LEN + 1 {
                    return Err(CliError::from(WouldBlock));
                }

                let domain_len = local_buf.get_u8_unchecked(CMD_HEAD_LEN);
                let total_len = CMD_HEAD_LEN + 1 + domain_len + 2;
                if local_buf.payload_len() < total_len {
                    return CliError::form(WouldBlock);
                }

                let bs = local_buf.peek(total_len);
                addr = str::from_utf8(bs[CMD_HEAD_LEN + 1..total_len - 2]).to_string();
                port = unsafe {
                    mem::transmute::<[u8; 2], u16>([bs[total_len - 2], bs[total_len - 1]]).from_be()
                };

                local_buf.consume(total_len);
            }

            AddrType::V6 => {
                if local_buf.payload_len() < CMD_IPV6_LEN {
                    return CliError::form(WouldBlock);
                }

                let bs = local_buf.peek(CMD_IPV6_LEN);
                let segments = [0u8; 16];
                segments
                    .as_mut()
                    .copy_from_slice(bs[CMD_HEAD_LEN..CMD_HEAD_LEN + 16]);
                addr = net::Ipv6Addr::from(segments);
                port = unsafe {
                    mem::transmute::<[u8; 2], u16>([bs[CMD_IPV6_LEN - 2], bs[CMD_IPV6_LEN]])
                        .from_be()
                };

                local_buf.consume(CMD_IPV6_LEN);
            }

            _ => {
                let response = [SOCKS5_VERSION, ADDRTYPE_NOT_SUPPORTED, 0, V4];
                self.write_buf_to(self.get_stream_mut(LOCAL), &response);

                error!("notsupported addrtype {}", atpy);

                return CliError::from(ADDRTYPE_NOT_SUPPORTED);
            }
        }

        match cmd {
            Cmd::CONNECT => {
                let host = format!("{}:{}", addr, port);
                info!("connect to host {}", host);
                
                TcpStream::connect(host.parse().unwrap())
                    .and_then(|sock| {
                        let entry = self.conns.vacant_entry();
                        let token = entry.key();
                        self.remote = Some(sock);
                        self.remote_token = token;
                        self.remote_interest = Ready::readable();
                        self.register(self.p, REMOTE)?;
                        self.stage = RemoteConnecting;

                        Ok(())
                    }).map_err(CliError::from);

            }

            _ => {
                let response = [SOCKS5_VERSION, CMD_NOT_SUPPORTED, 0, V4];
                self.write_buf_to(self.get_stream_mut(LOCAL), &response);

                error!("notsupported command {}", cmd);

                return CliError::from(CMD_NOT_SUPPORTED);
            }
        }
    }
    
    fn handle_remote_connected(&mut self, poll: &mut Poll, ev: &mio::Event) -> Result<(), CliError> {
        assert_eq!(self.remote_token, ev.token());
        
        let local_stream = self.get_stream(LOCAL);
        let local_buf = self.get_buf_mut(LOCAL);
        let remote_stream = self.get_stream(REMOTE);
        
        match local_buf.read_from(remote_stream) {
            Ok(0) => return CliError::from(UnexpectedEof),
            Err(ref e) if e.is_would_block() == false => return Err(*e),
            _ => (),
        }
        
        assert!(local_buf.payload_len() > 0);

        local_buf.write_to(remote_stream);


    fn handle_streaming(&mut self, poll: &mut Poll, ev: &mio::Event) -> Result<(), CliError> {

    }


    pub fn handle_events(
        &mut self,
        poll: &mut Poll,
        ev: &mio::Event,
        token: Token,
    ) -> Result<(), CliError> {
        let result = match self.stage {
            LocalConnected => self.handle_local_auth_method(poll, ev),

            WaitSndMethodSelReply => self.handle_local_snd_methodsel_reply(poll, ev),

            HandShake => self.handle_handshake(poll, ev),

            Streaming => self.handle_streaming(poll, ev),
        };

        Ok(())
    }
}
