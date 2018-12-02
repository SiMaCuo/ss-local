use super::err::{BufError::*, *};
use super::service::Service;
use super::socks5::{AddrType::*, Rep::*, Stage::*, *};
use mio::{self, net::TcpStream, Ready, Token};
use std::io::{self, ErrorKind::*, Read, Write};
use std::net::{self, IpAddr};
use std::{cmp, mem, ptr, str};
#[macro_use]
use log::*;

const BUF_ALLOC_SIZE: usize = 4096;
const MIN_VACANT_SIZE: usize = 512;
pub const LOCAL: bool = true;
pub const REMOTE: bool = false;
pub const REREGISTER: bool = true;
pub const REGISTER: bool = false;

fn is_wouldblock(e: &io::Error) -> bool {
    if e.kind() == WouldBlock || e.kind() == Interrupted {
        return true;
    }

    return false;
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

    pub fn read_u8(&mut self) -> Result<u8, CliError> {
        if self.payload_len() < 1 {
            return Err(CliError::from(InsufficientData));
        }

        let mut b = [0u8; 1];
        self.read_exact(&mut b);

        Ok(b[0])
    }

    pub fn read_port(&mut self) -> Result<u16, CliError> {
        if self.payload_len() < 2 {
            return Err(CliError::from(InsufficientData));
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
        unsafe { *self.buf.get_unchecked(index) }
    }

    pub fn peek(&self, size: usize) -> Result<&[u8], CliError> {
        if size > self.payload_len() {
            return Err(CliError::from(InsufficientData));
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
        let src = self.buf.as_ptr().add(self.pos);
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

    pub fn write_buf_to<W: Write>(&mut self, buf: &[u8], w: &mut W) -> io::Result<usize> {
        let buf_len = buf.len();
        if self.payload_len() > 0 {
            let _ = self.write(buf).unwrap();
            let _ = self.write_to(w);

            Ok(buf_len)
        } else {
            w.write(buf).and_then(|n| {
                if n < buf.len() {
                    self.write(&buf[n..]);
                }

                Ok(buf_len)
            })
        }
    }

    pub fn write_to<W: Write>(&mut self, w: &mut W) -> io::Result<usize> {
        if self.payload_len() == 0 {
            return Ok(0);
        }

        let mut total_write_len: usize = 0;
        loop {
            let result = w.write(&self.buf[self.pos..self.buf.len()]);
            match result {
                Ok(n) => {
                    total_write_len += n;
                    self.pos += n;
                    if self.payload_len() == 0 {
                        self.pos = 0;
                        unsafe {
                            self.buf.set_len(0);
                        }

                        return Ok(total_write_len);
                    }

                    if n == 0 {
                        return Ok(total_write_len);
                    }
                }

                Err(e) => {
                    if total_write_len > 0 {
                        return Ok(total_write_len);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    pub fn read_from<R: Read>(&mut self, r: &mut R) -> io::Result<usize> {
        let mut total_read_len: usize = 0;
        loop {
            let vacant_len = self.vacant_len();
            if vacant_len < MIN_VACANT_SIZE {
                if self.vacant_len() > 0 {
                    self.move_payload_to_head();
                }

                self.buf.reserve(BUF_ALLOC_SIZE);
            }

            let (start, end) = (self.buf.len(), self.buf.capacity());
            let result = r.read(&mut self.buf[start..end]);
            match result {
                Ok(n) => {
                    total_read_len += n;

                    if n == 0 {
                        return Ok(total_read_len);
                    }
                }

                Err(e) => {
                    if total_read_len > 0 {
                        return Ok(total_read_len);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }
}

impl Read for StreamBuf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.buf[self.head_vacant_len()..self.tail_vacant_len()])
            .read(buf)
            .and_then(|len| {
                self.pos += len;
                if self.pos == self.buf.len() {
                    self.pos = 0;
                    unsafe {
                        self.buf.set_len(0);
                    }
                }

                Ok(len)
            })
    }
}

impl Write for StreamBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.vacant_len() {
            if self.vacant_len() > 0 {
                self.move_payload_to_head();
            }

            let mul = buf.len() % BUF_ALLOC_SIZE + 1;
            self.buf.reserve(mul * BUF_ALLOC_SIZE);
        } else if buf.len() > self.tail_vacant_len() {
            self.move_payload_to_head();
        }

        let (start, end) = (self.buf.len(), self.buf.capacity());
        (&mut self.buf[start..end])
            .write(buf)
            .and_then(|n| {
                unsafe {
                    self.buf.set_len(self.buf.len() + n);
                }

                Ok(n)
            })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Connection<'c> {
    srv: &'c Service<'c>,
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

impl<'c> Connection<'c> {
    pub fn new(srv: &'c Service, local: TcpStream, local_token: Token, interest: Ready) -> Self {
        Connection {
            srv,
            local,
            local_token,
            local_buf: StreamBuf::new(),
            local_interest: interest,
            remote: None,
            remote_token: Token::from(std::usize::MAX),
            remote_buf: StreamBuf::new(),
            remote_interest: Ready::empty(),
            stage: LocalConnected,
        }
    }

    pub fn get_stream(&self, is_local_stream: bool) -> &TcpStream {
        if is_local_stream {
            &self.local
        } else {
            match self.remote {
                Some(ref s) => &s,

                None => unimplemented!(),
            }
        }
    }

    fn get_stream_mut(&mut self, is_local_stream: bool) -> &mut TcpStream {
        if is_local_stream {
            &mut self.local
        } else {
            match self.remote {
                Some(ref mut s) => s,

                None => unimplemented!(),
            }
        }
    }

    pub fn set_remote_stream(&mut self, stream: TcpStream) {
        assert!(self.remote.is_none());

        self.remote = Some(stream);
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

    pub fn get_interest(&self, is_local_stream: bool) -> Ready {
        if is_local_stream {
            self.local_interest
        } else {
            self.remote_interest
        }
    }

    pub fn set_interest(&mut self, interest: Ready, is_local_stream: bool) {
        if is_local_stream {
            self.local_interest = interest;
        } else {
            self.remote_interest = interest;
        }
    }

    pub fn shutdown(&mut self) {
        self.get_stream(LOCAL).shutdown(net::Shutdown::Both);
        self.srv.deregister_connection(self, LOCAL);

        if self.remote.is_some() {
            self.get_stream(REMOTE).shutdown(net::Shutdown::Both);
            self.srv.deregister_connection(self, REMOTE);
        }
    }

    fn handle_local_auth_method(&mut self) -> Result<(), CliError> {
        let buf = self.get_buf(LOCAL);
        if buf.payload_len() < METHOD_SELECT_HEAD_LEN {
            warn!(
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

        let method_sel_len = usize::from(nmethods) + METHOD_SELECT_HEAD_LEN;
        if method_sel_len > buf.payload_len() {
            warn!(
                "auth {}, recive data size {} less than need {}.",
                self.local.peer_addr()?,
                buf.payload_len(),
                method_sel_len
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

        self.get_buf_mut(LOCAL).consume(method_sel_len);

        if method != Method::NO_AUTH {
            return Err(CliError::from(Method::NO_ACCEPT_METHOD));
        }

        let mut no_auth = [SOCKS5_VERSION; 2];
        no_auth[1] = Method::NO_AUTH;

        let local_stream = self.get_stream_mut(LOCAL);
        match local_stream.write(&no_auth) {
            Err(e) => {
                let err = CliError::from(e);
                if err.is_wouldblock() {
                    self.set_interest(Ready::writable(), LOCAL);
                }

                Err(err)
            }

            Ok(_) => {
                self.stage = HandShake;
                Ok(())
            }
        }
    }

    fn handle_local_snd_methodsel_reply(&mut self) -> Result<(), CliError> {
        let mut no_auth = [SOCKS5_VERSION, Method::NO_AUTH];

        let local_stream = self.get_stream_mut(LOCAL);
        local_stream
            .write(&no_auth)
            .and_then(|_| {
                self.stage = HandShake;
                Ok(())
            }).map_err(CliError::from)
    }

    fn handle_handshake(&mut self) -> Result<(), CliError> {
        let local_buf = self.get_buf(LOCAL);
        let head = local_buf.peek(4)?;
        let (ver, cmd, _, atpy) = (head[0], head[1], head[2], head[3]);
        if ver != SOCKS5_VERSION {
            return Err(CliError::from(Rep::GENERAL_FAILURE));
        }

        let mut addr: String = "0.0.0.0".to_string();
        let mut port: u16 = u16::max_value();
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
                port = unsafe { u16::from_be(mem::transmute::<[u8; 2], u16>([bs[8], bs[9]])) };

                self.get_buf_mut(LOCAL).consume(CMD_IPV4_LEN);
            }

            AddrType::DOMAIN => {
                if local_buf.payload_len() < CMD_HEAD_LEN + 1 {
                    return Err(CliError::from(WouldBlock));
                }

                let domain_len = usize::from(local_buf.get_u8_unchecked(CMD_HEAD_LEN));
                let total_len = CMD_HEAD_LEN + 1 + domain_len + 2;
                if local_buf.payload_len() < total_len {
                    return Err(CliError::from(WouldBlock));
                }

                let bs = local_buf.peek(total_len)?;
                addr = str::from_utf8(&bs[CMD_HEAD_LEN + 1..total_len - 2])
                    .unwrap()
                    .to_string();
                port = unsafe {
                    u16::from_be(mem::transmute::<[u8; 2], u16>([
                        bs[total_len - 2],
                        bs[total_len - 1],
                    ]))
                };

              self.get_buf_mut(REMOTE).consume(total_len);
            }

            AddrType::V6 => {
                if local_buf.payload_len() < CMD_IPV6_LEN {
                    return Err(CliError::from(WouldBlock));
                }

                let bs = local_buf.peek(CMD_IPV6_LEN)?;
                let mut segments = [0u8; 16];
                segments
                    .as_mut()
                    .copy_from_slice(&bs[CMD_HEAD_LEN..CMD_HEAD_LEN + 16]);
                addr = net::Ipv6Addr::from(segments).to_string();
                port = unsafe {
                    u16::from_be(mem::transmute::<[u8; 2], u16>([
                        bs[CMD_IPV6_LEN - 2],
                        bs[CMD_IPV6_LEN],
                    ]))
                };

                self.get_buf_mut(LOCAL).consume(CMD_IPV6_LEN);
            }

            _ => {
                let response = [SOCKS5_VERSION, ADDRTYPE_NOT_SUPPORTED, 0, V4];
                error!("notsupported addrtype {}", atpy);
                self.get_stream_mut(LOCAL).write(&response).map_err(|e| {
                    warn!("write ADDRTYPE_NOT_SUPPORTED failed: {}", e);

                    CliError::from(GENERAL_FAILURE)
                });
            }
        }

        match cmd {
            Cmd::CONNECT => {
                let host = format!("{}:{}", addr, port);
                info!("connect to host {}", host);

                TcpStream::connect(&host.parse().unwrap())
                    .and_then(|sock| {
                        if let Err(e) = self.srv.register_remote_connection(sock, self) {
                            debug!("register remote connection failed: {}", e);

                            return Err(e);
                        }

                        if let Err(e) = self.srv.deregister_connection(self, LOCAL) {
                            debug!(
                                "deregister LOCAL connection failed when connecte to remote: {}",
                                e
                            );

                            return Err(e);
                        }

                        self.stage = RemoteConnecting;

                        Ok(())
                    }).map_err(CliError::from)
            }

            _ => {
                let response = [SOCKS5_VERSION, CMD_NOT_SUPPORTED, 0, V4];
                self.get_stream_mut(LOCAL).write(&response).unwrap();

                error!("notsupported command {}", cmd);

                return Err(CliError::from(CMD_NOT_SUPPORTED));
            }
        }
    }

    fn handle_remote_connected(&mut self, ev: &mio::Event) -> Result<(), CliError> {
        assert_eq!(self.get_token(REMOTE), ev.token());

        let remote_stream = self.get_stream(REMOTE);
        let sock_addr = remote_stream.local_addr()?;
        let port = sock_addr.port();
        let mut write_result: io::Result<usize> = Ok(0);
        let mut need_write_len: usize = 0;
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
                response[22] = (port.to_be() & 0xff) as u8;
                write_result = self.get_stream_mut(LOCAL).write(&response);
            }
        }

        match write_result {
            Ok(n) => {
                if n != need_write_len {
                    warn!("write {} bytes response to remote connect, need {} bytes, close connection.", n, need_write_len);

                    Err(CliError::from(GENERAL_FAILURE))
                } else {
                    self.srv.register_connection(self, Ready::readable(), LOCAL);
                    self.stage = Streaming;

                    Ok(())
                }
            }

            Err(e) => {
                warn!(
                    "write response when remote connected failed with error: {}",
                    e
                );

                Err(CliError::from(e))
            }
        }
    }

    fn handle_streaming(&mut self, ev: &mio::Event) -> Result<(), CliError> {
        let token = ev.token();
        if ev.readiness().is_readable() {
            if token == self.get_token(LOCAL) {
                let remote_buf = self.get_buf_mut(REMOTE);
                match remote_buf.read_from(self.get_stream_mut(LOCAL)) {
                    Ok(read_len) => {
                        if read_len == 0 {
                            return Err(CliError::from(UnexpectedEof));
                        }

                        match remote_buf.write_to(self.get_stream_mut(REMOTE)) {
                            Ok(write_len) => {
                                if write_len != read_len {
                                    if self.get_interest(REMOTE) != Ready::empty() {
                                        return self
                                            .srv
                                            .reregister_connection(
                                                self,
                                                self.get_interest(REMOTE) | Ready::writable(),
                                                REMOTE,
                                            ).map_err(CliError::from);
                                    } else {
                                        return self
                                            .srv
                                            .register_connection(self, Ready::writable(), REMOTE)
                                            .map_err(CliError::from);
                                    }
                                }

                                return Ok(());
                            }

                            Err(e) => {
                                return Err(CliError::from(e));
                            }
                        }
                    }

                    Err(e) => {
                        return Err(CliError::from(e));
                    }
                }
            } else if token == self.get_token(REMOTE) {
                let local_buf = self.get_buf_mut(LOCAL);
                match local_buf.read_from(self.get_stream_mut(REMOTE)) {
                    Ok(read_len) => {
                        if read_len == 0 {
                            return Err(CliError::from(UnexpectedEof));
                        }

                        match local_buf.write_to(self.get_stream_mut(LOCAL)) {
                            Ok(write_len) => {
                                if write_len != read_len {
                                    if self.get_interest(LOCAL) != Ready::empty() {
                                        return self
                                            .srv
                                            .reregister_connection(
                                                self,
                                                self.get_interest(LOCAL) | Ready::writable(),
                                                LOCAL,
                                            ).map_err(CliError::from);
                                    } else {
                                        return self
                                            .srv
                                            .register_connection(self, Ready::writable(), LOCAL)
                                            .map_err(CliError::from);
                                    }
                                }

                                return Ok(());
                            }

                            Err(e) => {
                                return Err(CliError::from(e));
                            }
                        }
                    }

                    Err(e) => {
                        return Err(CliError::from(e));
                    }
                }
            } else {
                unreachable!();
            }
        } else if ev.readiness().is_writable() {
            if token == self.get_token(LOCAL) {
                let remote_buf = self.get_buf_mut(REMOTE);
                let total_payload_len = remote_buf.payload_len();
                if total_payload_len == 0 {
                    return self
                        .srv
                        .reregister_connection(self, Ready::readable(), LOCAL)
                        .map_err(CliError::from);
                }

                let local_stream = self.get_stream_mut(LOCAL);
                match remote_buf.write_to(local_stream) {
                    Ok(n) => {
                        if n == total_payload_len {
                            return self
                                .srv
                                .reregister_connection(self, Ready::readable(), LOCAL)
                                .map_err(CliError::from);
                        }

                        return Ok(());
                    }

                    Err(e) => {
                        if is_wouldblock(&e) {
                            return Ok(());
                        }

                        return Err(CliError::from(e));
                    }
                }
            } else if token == self.get_token(REMOTE) {
                let local_buf = self.get_buf_mut(LOCAL);
                let total_payload_len = local_buf.payload_len();
                if total_payload_len == 0 {
                    return self
                        .srv
                        .reregister_connection(self, Ready::readable(), REMOTE)
                        .map_err(CliError::from);
                }

                //let remote_stream = self.get_stream_mut(REMOTE);
                match local_buf.write_to(self.remote.as_mut().unwrap()) {
                    Ok(n) => {
                        if n == total_payload_len {
                            return self
                                .srv
                                .reregister_connection(self, Ready::readable(), REMOTE)
                                .map_err(CliError::from);
                        }

                        return Ok(());
                    }

                    Err(e) => {
                        if is_wouldblock(&e) {
                            return Ok(());
                        }

                        return Err(CliError::from(e));
                    }
                }
            } else {
                unreachable!();
            }
        }

        Ok(())
    }

    pub fn handle_events(&mut self, ev: &mio::Event) -> Result<(), CliError> {
        let _result = match self.stage {
            LocalConnected => self.handle_local_auth_method(),

            SendMethodSelect => self.handle_local_snd_methodsel_reply(),

            HandShake => self.handle_handshake(),

            RemoteConnecting => self.handle_remote_connected(ev),

            Streaming => self.handle_streaming(ev),
        };

        Ok(())
    }
}
