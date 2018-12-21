use super::err::*;
use super::socks5::{AddrType::*, Rep::*, Stage::*, *};
use log::{debug, error, info, warn};
use mio::{self, net::TcpStream, Poll, PollOpt, Ready, Token};
use std::io::{self, Error, ErrorKind::*, Read, Write};
use std::net::{self, IpAddr, ToSocketAddrs};
use std::{cmp, fmt, mem, ptr, str};

const BUF_ALLOC_SIZE: usize = 4096;
const MIN_VACANT_SIZE: usize = 128;

pub const LOCAL: bool = true;
pub const REMOTE: bool = false;

struct Guard<'a> {
    buf: &'a mut Vec<u8>,
    len: usize,
}

impl<'a> Drop for Guard<'a> {
    fn drop(&mut self) {
        unsafe {
            self.buf.set_len(self.len);
        }
    }
}

pub fn is_wouldblock(e: &io::Error) -> bool {
    if e.kind() == WouldBlock || e.kind() == Interrupted {
        return true;
    }

    return false;
}

fn do_read_from<R: Read>(r: &mut R, v: &mut Vec<u8>) -> io::Result<usize> {
    let start_len = v.len();
    let capacity = v.capacity();

    if start_len == capacity {
        debug!("\t\t start_len == capacity");

        return Err(Error::from(InvalidInput));
    }

    let mut g = Guard {
        len: v.len(),
        buf: v,
    };

    unsafe {
        g.buf.set_len(capacity);
    }
    loop {
        match r.read(&mut g.buf[g.len..]) {
            Ok(n) => {
                g.len += n;
                if n == 0 || g.len == g.buf.capacity() {
                    return Ok(g.len - start_len);
                }
            }

            Err(e) => return Err(e),
        }
    }
}

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

    pub fn get_u8_unchecked(&self, index: usize) -> u8 {
        unsafe { *self.buf.get_unchecked(index) }
    }

    pub fn peek(&self, size: usize) -> Result<&[u8], CliError> {
        if size > self.payload_len() {
            return Err(CliError::from(InvalidInput));
        }

        Ok(&self.buf[self.pos..self.pos + size])
    }

    pub fn consume(&mut self, size: usize) -> Result<usize, CliError> {
        let n = cmp::min(self.payload_len(), size);
        self.pos += n;
        if self.payload_len() == 0 {
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

    fn move_payload_to_head(&mut self) {
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
        let src = unsafe { self.buf.as_ptr().add(self.pos) };
        let dst = self.buf.as_mut_ptr();
        unsafe {
            if len < self.head_vacant_len() {
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
            debug!("\t\t write_to, buffer is empty.");

            return Ok(0);
        }

        let mut total_write_len: usize = 0;
        let rls = loop {
            let result = if self.payload_len() > BUF_ALLOC_SIZE {
                w.write(&self.buf[self.pos..self.pos + BUF_ALLOC_SIZE])
            } else {
                w.write(&self.buf[self.pos..])
            };

            match result {
                Ok(n) => {
                    total_write_len += n;
                    self.pos += n;
                    if self.payload_len() == 0 {
                        break Ok(total_write_len);
                    }

                    if n == 0 {
                        debug!("\t\t total write length {}", total_write_len);

                        break Ok(total_write_len);
                    }
                }

                Err(e) => {
                    if total_write_len > 0 {
                        debug!("\t\t write some bytes, but some error happed {}", e);

                        break Ok(total_write_len);
                    } else {
                        debug!("\t\t write to return with error {}", e);

                        break Err(e);
                    }
                }
            }
        };

        if self.payload_len() == 0 {
            if self.buf.capacity() > 2 * BUF_ALLOC_SIZE {
                debug!("\t\t cap len {}, resize data buf", self.buf.capacity());

                self.buf.resize(BUF_ALLOC_SIZE, 0u8);
            }

            self.pos = 0;
            unsafe {
                self.buf.set_len(0);
            }
        }

        rls
    }

    pub fn read_from<R: Read>(&mut self, r: &mut R) -> io::Result<usize> {
        do_read_from(r, &mut self.buf)
    }

    pub fn copy<R, W>(&mut self, r: &mut R, w: &mut W) -> io::Result<usize>
    where
        R: Read,
        W: Write,
    {
        if self.payload_len() > 0 {
            let _ = self.write_to(w);
        }

        let mut total_rd_len: usize = 0;
        let mut loop_payload_len: usize = 0;
        let mut write_wouldblock: bool = false;
        let rls = loop {
            let rd_rls = self.read_from(r);
            match rd_rls {
                Ok(rd_len) => {
                    if rd_len == 0 {
                        break Ok(0);
                    }

                    total_rd_len += rd_len;
                    if write_wouldblock == false {
                        let _ = self
                            .write_to(w)
                            .and_then(|wd_len| {
                                if self.payload_len() > 0 {
                                    debug!(
                                        "\t read {}, write {}, payload {}",
                                        rd_len,
                                        wd_len,
                                        self.payload_len()
                                    );

                                    loop_payload_len += self.payload_len();
                                }

                                Ok(wd_len)
                            })
                            .map_err(|e| {
                                debug!("\t write to targe failed {}", e);
                                write_wouldblock = true;

                                e
                            });
                    }

                    if self.vacant_len() < MIN_VACANT_SIZE {
                        if self.head_vacant_len() > 0 {
                            self.move_payload_to_head();
                        }

                        self.buf.reserve(BUF_ALLOC_SIZE);
                        debug!("\t cap len 01 {}", self.buf.capacity());
                    }
                }

                Err(e) => {
                    if total_rd_len > 0 {
                        total_rd_len += self.payload_len() - loop_payload_len;

                        break Ok(total_rd_len);
                    } else {
                        break Err(e);
                    }
                }
            }
        };

        if self.payload_len() > 0 {
            let _ = self.write_to(w);
        }

        if self.buf.capacity() > BUF_ALLOC_SIZE {
            let payload_len = self.payload_len();
            if payload_len + MIN_VACANT_SIZE < BUF_ALLOC_SIZE {
                self.buf.reserve(BUF_ALLOC_SIZE - payload_len);
                debug!("\t cap len 02 {}", self.buf.capacity());
            }
        }

        rls
    }
}

pub struct Connection {
    local: Option<TcpStream>,
    local_token: Token,
    local_buf: StreamBuf,
    local_readiness: Ready,
    remote: Option<TcpStream>,
    host: String,
    remote_token: Token,
    remote_buf: StreamBuf,
    remote_readiness: Ready,
    stage: Stage,
    shutdown: bool,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            local: None,
            local_token: Token::from(std::usize::MAX),
            local_buf: StreamBuf::new(),
            local_readiness: Ready::empty(),
            remote: None,
            host: "*".to_string(),
            remote_token: Token::from(std::usize::MAX),
            remote_buf: StreamBuf::new(),
            remote_readiness: Ready::empty(),
            stage: LocalConnected,
            shutdown: false,
        }
    }

    pub fn register(
        &mut self,
        poll: &Poll,
        handle: TcpStream,
        token: Token,
        readiness: Ready,
        opts: PollOpt,
        is_local_stream: bool,
    ) -> io::Result<()> {
        poll.register(&handle, token, readiness, opts)
            .and_then(|_| {
                self.set_stream(handle, is_local_stream);
                self.set_token(token, is_local_stream);
                self.set_readiness(readiness, is_local_stream);

                Ok(())
            })
    }

    fn reregister(
        &mut self,
        poll: &Poll,
        readiness: Ready,
        opts: PollOpt,
        is_local_stream: bool,
    ) -> io::Result<()> {
        let stream = self.get_stream(is_local_stream);
        let token = self.get_token(is_local_stream);

        poll.reregister(stream, token, readiness, opts)
            .and_then(|_| {
                self.set_readiness(readiness, is_local_stream);

                Ok(())
            })
    }

    fn get_stream(&self, is_local_stream: bool) -> &TcpStream {
        if is_local_stream {
            match self.local {
                Some(ref s) => &s,

                None => unreachable!(),
            }
        } else {
            match self.remote {
                Some(ref s) => &s,

                None => unreachable!(),
            }
        }
    }

    fn get_stream_mut(&mut self, is_local_stream: bool) -> &mut TcpStream {
        if is_local_stream {
            self.local.as_mut().unwrap()
        } else {
            self.remote.as_mut().unwrap()
        }
    }

    fn set_stream(&mut self, stream: TcpStream, is_local_stream: bool) {
        if is_local_stream {
            self.local = Some(stream);
        } else {
            self.remote = Some(stream);
        }
    }

    fn get_buf(&self, is_local_stream: bool) -> &StreamBuf {
        if is_local_stream {
            &self.local_buf
        } else {
            &self.remote_buf
        }
    }

    pub fn get_token(&self, is_local_stream: bool) -> Token {
        if is_local_stream {
            self.local_token
        } else {
            self.remote_token
        }
    }

    pub fn set_token(&mut self, token: Token, is_local_stream: bool) {
        if is_local_stream {
            self.local_token = token;
        } else {
            self.remote_token = token;
        }
    }

    fn get_readiness(&self, is_local_stream: bool) -> Ready {
        if is_local_stream {
            self.local_readiness
        } else {
            self.remote_readiness
        }
    }

    fn set_readiness(&mut self, readiness: Ready, is_local_stream: bool) {
        if is_local_stream {
            self.local_readiness = readiness;
        } else {
            self.remote_readiness = readiness;
        }
    }

    pub fn shutdown(&mut self, poll: &Poll) {
        if self.shutdown == true {
            return;
        }

        self.shutdown = true;

        self.set_readiness(Ready::empty(), LOCAL);
        let local_stream = self.get_stream(LOCAL);
        let _ = local_stream.shutdown(net::Shutdown::Both);
        let _ = poll.deregister(local_stream);

        self.set_readiness(Ready::empty(), REMOTE);
        if self.remote.is_some() {
            let remote_stream = self.get_stream(REMOTE);
            let _ = remote_stream.shutdown(net::Shutdown::Both);
            let _ = poll.deregister(remote_stream);
        }
    }

    pub fn handle_local_auth_method(&mut self, poll: &Poll) -> Result<(), CliError> {
        debug!("handle_local_auth_method @{}", *self);

        match (&mut self.local_buf).read_from(self.local.as_mut().unwrap()) {
            Ok(n) => {
                if n == 0 {
                    return Err(CliError::from(UnexpectedEof));
                }
            }

            Err(e) => {
                if is_wouldblock(&e) == false {
                    return Err(CliError::from(e));
                }
            }
        }

        let buf = self.get_buf(LOCAL);
        if buf.payload_len() < METHOD_SELECT_HEAD_LEN {
            warn!(
                "auth, recive data less than  {} bytes @{}",
                METHOD_SELECT_HEAD_LEN, *self
            );

            return Ok(());
        }

        let head = buf.peek(METHOD_SELECT_HEAD_LEN)?;
        let (ver, nmethods) = (head[0], head[1]);
        if ver != SOCKS5_VERSION {
            return Err(CliError::from(InvalidData));
        }

        let method_sel_len = usize::from(nmethods) + METHOD_SELECT_HEAD_LEN;
        if method_sel_len > buf.payload_len() {
            warn!(
                "auth, recive data size {} less than need {} @{}",
                buf.payload_len(),
                method_sel_len,
                *self
            );

            return Ok(());
        }

        let mut method = Method::NO_ACCEPT_METHOD;
        let sel = buf.peek(method_sel_len)?;
        for pos in 0..nmethods as usize {
            if sel[METHOD_SELECT_HEAD_LEN + pos] == Method::NO_AUTH {
                method = Method::NO_AUTH;
                break;
            }
        }

        &mut self.local_buf.consume(method_sel_len);

        if method != Method::NO_AUTH {
            return Err(CliError::from(Method::NO_ACCEPT_METHOD));
        }

        let mut no_auth = [SOCKS5_VERSION; 2];
        no_auth[1] = Method::NO_AUTH;

        let rlt = self.get_stream_mut(LOCAL).write(&no_auth);
        match rlt {
            Err(e) => {
                let err = CliError::from(e);
                if err.is_wouldblock() {
                    if let Err(e) = self.reregister(
                        poll,
                        Ready::writable(),
                        PollOpt::edge() | PollOpt::oneshot(),
                        LOCAL,
                    ) {
                        debug!("auth, re-register LOCAL writable FAILED {}, @{}", e, *self);

                        return Err(CliError::from(e));
                    }

                    self.stage = SendMethodSelect;

                    return Ok(());
                }

                Err(err)
            }

            Ok(_) => {
                self.stage = HandShake;

                Ok(())
            }
        }
    }

    fn handle_local_snd_methodsel_reply(&mut self, poll: &Poll) -> Result<(), CliError> {
        debug!("handle_local_snd_methodsel_reply @{}", *self);

        if let Err(e) = self.reregister(poll, Ready::readable(), PollOpt::edge(), LOCAL) {
            debug!(
                "auth, re-register LOCAL readable oneshot FAILED {}, @{}",
                e, *self
            );

            return Err(CliError::from(e));
        }

        let no_auth = [SOCKS5_VERSION, Method::NO_AUTH];
        self.get_stream_mut(LOCAL)
            .write(&no_auth)
            .and_then(|_| {
                self.stage = HandShake;
                Ok(())
            })
            .map_err(CliError::from)
    }

    fn handle_handshake(&mut self, poll: &Poll) -> Result<(), CliError> {
        debug!("handle_handshake @{}", *self);

        match (&mut self.local_buf).read_from(self.local.as_mut().unwrap()) {
            Ok(n) => {
                if n == 0 {
                    return Err(CliError::from(UnexpectedEof));
                }
            }

            Err(e) => {
                if is_wouldblock(&e) == false {
                    return Err(CliError::from(e));
                }
            }
        }

        let head = self.local_buf.peek(4)?;
        let (ver, cmd, _, atpy) = (head[0], head[1], head[2], head[3]);
        if ver != SOCKS5_VERSION {
            warn!(
                "handshake, need socks version 5, recive version {} @{}",
                ver, *self
            );

            return Err(CliError::from(Rep::GENERAL_FAILURE));
        }

        let mut addr: String = "0.0.0.0".to_string();
        let mut port: u16 = u16::max_value();
        match atpy {
            AddrType::V4 => {
                if self.local_buf.payload_len() < CMD_IPV4_LEN {
                    debug!("handshake, ipv4, need {} bytes at least, but only {} bytes recived, need more data @{}", CMD_IPV4_LEN, self.local_buf.payload_len(), *self);

                    return Err(CliError::from(WouldBlock));
                }

                let bs = self.local_buf.peek(CMD_IPV4_LEN)?;
                addr = net::Ipv4Addr::new(
                    bs[CMD_HEAD_LEN],
                    bs[CMD_HEAD_LEN + 1],
                    bs[CMD_HEAD_LEN + 2],
                    bs[CMD_HEAD_LEN + 3],
                )
                .to_string();
                port = unsafe { u16::from_be(mem::transmute::<[u8; 2], u16>([bs[8], bs[9]])) };

                debug!("handshake, ipv4 {}:{} @{}", addr, port, *self);

                (&mut self.local_buf).consume(CMD_IPV4_LEN)?;
            }

            AddrType::DOMAIN => {
                if self.local_buf.payload_len() < CMD_HEAD_LEN + 1 {
                    debug!(
                        "handshake, domain head len {}, but payload len {}, need more data @{}",
                        CMD_HEAD_LEN,
                        self.local_buf.payload_len(),
                        *self
                    );

                    return Err(CliError::from(WouldBlock));
                }

                let domain_len = usize::from(self.local_buf.get_u8_unchecked(CMD_HEAD_LEN));
                let total_len = CMD_HEAD_LEN + 1 + domain_len + 2;
                if self.local_buf.payload_len() < total_len {
                    debug!(
                        "handshake, domain total len {}, but payload len {}, need more data @{}",
                        total_len,
                        self.local_buf.payload_len(),
                        *self
                    );

                    return Err(CliError::from(WouldBlock));
                }

                let bs = self.local_buf.peek(total_len)?;
                addr = str::from_utf8(&bs[CMD_HEAD_LEN + 1..total_len - 2])
                    .unwrap()
                    .to_string();
                port = unsafe {
                    u16::from_be(mem::transmute::<[u8; 2], u16>([
                        bs[total_len - 2],
                        bs[total_len - 1],
                    ]))
                };

                debug!("handshake domain {}:{}, @{}", addr, port, *self);

                (&mut self.local_buf).consume(total_len)?;
            }

            AddrType::V6 => {
                if self.local_buf.payload_len() < CMD_IPV6_LEN {
                    debug!("handshake, ipv6, head need {} bytes at least, but only {} bytes recived, need more data @{}", CMD_IPV6_LEN, self.local_buf.payload_len(), *self);

                    return Err(CliError::from(WouldBlock));
                }

                let bs = self.local_buf.peek(CMD_IPV6_LEN)?;
                let mut segments = [0u8; 16];
                segments
                    .as_mut()
                    .copy_from_slice(&bs[CMD_HEAD_LEN..CMD_HEAD_LEN + 16]);
                addr = net::Ipv6Addr::from(segments).to_string();
                port = unsafe {
                    u16::from_be(mem::transmute::<[u8; 2], u16>([
                        bs[CMD_IPV6_LEN - 2],
                        bs[CMD_IPV6_LEN - 1],
                    ]))
                };

                debug!("handshake, ipv6 {}:{}, @{}", addr, port, *self);

                self.local_buf.consume(CMD_IPV6_LEN)?;
            }

            _ => {
                let response = [SOCKS5_VERSION, ADDRTYPE_NOT_SUPPORTED, 0, V4];
                error!("notsupported addrtype {} @{}", atpy, *self);
                if let Err(e) = self.get_stream_mut(LOCAL).write(&response) {
                    warn!("write ADDRTYPE_NOT_SUPPORTED failed: {} @{}", e, *self);

                    return Err(CliError::from(GENERAL_FAILURE));
                }
            }
        }

        match cmd {
            Cmd::CONNECT => {
                self.host = format!("{}:{}", addr, port);
                info!("connect to host {}", self.host);

                let addrs_result = self.host.to_socket_addrs();
                if let Err(e) = addrs_result {
                    error!("resolve host failed {}", e);

                    return Err(CliError::from(e));
                }

                TcpStream::connect(addrs_result.unwrap().next().as_ref().unwrap())
                    .and_then(|sock| {
                        let rlt = self.register(
                            poll,
                            sock,
                            self.get_token(REMOTE),
                            Ready::writable(),
                            PollOpt::edge(),
                            REMOTE,
                        );
                        if let Err(e) = rlt {
                            debug!("register remote connection failed: {} @{}", e, *self);

                            return Err(e);
                        }

                        self.stage = RemoteConnecting;

                        Ok(())
                    })
                    .map_err(CliError::from)
            }

            _ => {
                let response = [SOCKS5_VERSION, CMD_NOT_SUPPORTED, 0, V4];
                self.get_stream_mut(LOCAL).write(&response).unwrap();

                error!("notsupported command {} @{}", cmd, *self);

                return Err(CliError::from(CMD_NOT_SUPPORTED));
            }
        }
    }

    fn handle_remote_connected(&mut self, ev: &mio::Event) -> Result<(), CliError> {
        debug!("triger remote connected event @{}", *self);

        assert_eq!(self.get_token(REMOTE), ev.token());

        let remote_stream = self.get_stream(REMOTE);
        remote_stream
            .take_error()
            .and_then(|option| {
                if let Some(e) = option {
                    debug!("connected FAILED {}, @{}", e, *self);

                    let response = [SOCKS5_VERSION, HOST_UNREACHABLE, 0, V4];
                    let _ = self.get_stream(LOCAL).write(&response);

                    Err(e)
                } else {
                    Ok(())
                }
            })
            .map_err(CliError::from)?;

        let sock_addr = remote_stream.local_addr()?;
        let port = sock_addr.port();
        let write_result;
        let need_write_len;
        match sock_addr.ip() {
            IpAddr::V4(addr) => {
                let mut response = [SOCKS5_VERSION, SUCCEEDED, 0, V4, 0, 0, 0, 0, 0, 0];
                need_write_len = response.len();
                &mut response[4..8].copy_from_slice(&addr.octets());

                let bs: [u8; 2] = unsafe { mem::transmute::<u16, [u8; 2]>(port.to_be()) };
                &mut response[8..].copy_from_slice(&bs);
                write_result = self.get_stream_mut(LOCAL).write(&response);
            }

            IpAddr::V6(addr) => {
                let mut response = [SOCKS5_VERSION; 22];
                need_write_len = response.len();
                response[1] = SUCCEEDED;
                response[2] = 0;
                response[3] = V6;
                &mut response[4..20].copy_from_slice(&addr.octets());
                response[20] = (port.to_be() >> 1) as u8;
                response[21] = (port.to_be() & 0xff) as u8;
                write_result = self.get_stream_mut(LOCAL).write(&response);
            }
        }

        match write_result {
            Ok(n) => {
                if n != need_write_len {
                    warn!(
                        "write {} bytes response to remote connect, need {} bytes @{}",
                        n, need_write_len, *self
                    );

                    Err(CliError::from(GENERAL_FAILURE))
                } else {
                    self.stage = Streaming;

                    Ok(())
                }
            }

            Err(e) => {
                warn!(
                    "write response when remote connected failed with error: {} @{}",
                    e, *self
                );

                Err(CliError::from(e))
            }
        }
    }

    fn handle_streaming(&mut self, poll: &Poll, ev: &mio::Event) -> Result<(), CliError> {
        debug!("streaming, {}", *self);

        let token = ev.token();
        if ev.readiness().is_readable() {
            if token == self.get_token(LOCAL) {
                debug!("\tlocal readable");

                let buf = &mut self.remote_buf;
                match buf.copy(self.local.as_mut().unwrap(), self.remote.as_mut().unwrap()) {
                    Ok(n) => {
                        if n == 0 {
                            return Err(CliError::from(UnexpectedEof));
                        }
                    }

                    Err(e) => {
                        if is_wouldblock(&e) == false {
                            return Err(CliError::from(e));
                        }
                    }
                }

                let mut readiness = Ready::readable();
                if buf.payload_len() > 0 {
                    readiness |= Ready::writable();
                }

                if readiness != self.get_readiness(REMOTE) {
                    debug!("\t\t change remote sock readiness {:?}", readiness);

                    return self
                        .reregister(poll, readiness, PollOpt::edge(), REMOTE)
                        .map_err(CliError::from);
                }

                return Ok(());
            } else if token == self.get_token(REMOTE) {
                debug!("\tremote readable.");

                let buf = &mut self.local_buf;
                match buf.copy(self.remote.as_mut().unwrap(), self.local.as_mut().unwrap()) {
                    Ok(n) => {
                        if n == 0 {
                            debug!("\t\t read zero bytes @{}", *self);
                            return Err(CliError::from(UnexpectedEof));
                        }
                    }

                    Err(e) => {
                        if is_wouldblock(&e) == false {
                            return Err(CliError::from(e));
                        }
                    }
                }

                let mut readiness = Ready::readable();
                if buf.payload_len() > 0 {
                    readiness |= Ready::writable();
                }

                if readiness != self.get_readiness(LOCAL) {
                    debug!("\t\t change local sock readiness {:?}", readiness);

                    return self
                        .reregister(poll, readiness, PollOpt::edge(), LOCAL)
                        .map_err(CliError::from);
                }
            } else {
                unreachable!();
            }
        } else if ev.readiness().is_writable() {
            if token == self.get_token(LOCAL) {
                let payload_len = self.get_buf(LOCAL).payload_len();
                debug!(
                    "\tlocal writable, payload length {} {}, @{}",
                    payload_len,
                    &self.local_buf.payload_len(),
                    *self
                );

                if payload_len == 0 {
                    let _ = self.reregister(poll, Ready::readable(), PollOpt::edge(), LOCAL);

                    return Ok(());
                }

                let mut write_len: usize = 0;
                loop {
                    let rls = (&mut self.local_buf).write_to(self.local.as_mut().unwrap());
                    match rls {
                        Ok(n) => {
                            if n == 0 {
                                debug!("\t  local buf write to local sock zero bytes");

                                return Ok(());
                            }

                            debug!(
                                "\t  write length {}, payload len {}",
                                n,
                                self.get_buf(LOCAL).payload_len()
                            );

                            write_len += n;
                            if write_len == payload_len {
                                self.reregister(poll, Ready::readable(), PollOpt::edge(), LOCAL)?;

                                return Ok(());
                            }
                        }

                        Err(e) => {
                            if is_wouldblock(&e) {
                                return Ok(());
                            }

                            return Err(CliError::from(e));
                        }
                    }
                }
            } else if token == self.get_token(REMOTE) {
                let payload_len = self.get_buf(REMOTE).payload_len();
                debug!("\tremote writable, payload length {}", payload_len);

                if payload_len == 0 {
                    self.reregister(poll, Ready::readable(), PollOpt::edge(), REMOTE)
                        .map_err(CliError::from)?;
                }

                let mut write_len: usize = 0;
                loop {
                    let rls = (&mut self.remote_buf).write_to(self.remote.as_mut().unwrap());
                    match rls {
                        Ok(n) => {
                            if n == 0 {
                                return Ok(());
                            }

                            write_len += n;
                            if write_len == payload_len {
                                self.reregister(poll, Ready::readable(), PollOpt::edge(), REMOTE)
                                    .map_err(CliError::from)?;
                            }
                        }

                        Err(e) => {
                            if is_wouldblock(&e) {
                                return Ok(());
                            }

                            return Err(CliError::from(e));
                        }
                    }
                }
            } else {
                unreachable!();
            }
        }

        Ok(())
    }

    pub fn handle_events(&mut self, poll: &Poll, ev: &mio::Event) -> Result<(), CliError> {
        let rlt = match self.stage {
            LocalConnected => self.handle_local_auth_method(poll),

            SendMethodSelect => self.handle_local_snd_methodsel_reply(poll),

            HandShake => self.handle_handshake(poll),

            RemoteConnecting => self.handle_remote_connected(ev),

            Streaming => self.handle_streaming(poll, ev),
        };

        rlt
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s0 = match self.local {
            Some(ref l) => format!("local :{}", l.peer_addr().unwrap().port(),),

            None => "local *".to_string(),
        };

        let s1 = format!("[{:?}] remote {} <->", self.stage, self.host);

        write!(f, "{}", [s1, s0].concat())
    }
}
