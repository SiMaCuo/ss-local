use super::err::{NetError::*, *};
use super::shut::*;
use super::socks5::{AddrType::*, Rep::*, Stage::*, *};
use log::{debug, error, warn};
use mio::{self, net::TcpStream, Poll, PollOpt, Ready, Token};
use std::io::{self, Error, ErrorKind::*, Read, Write};
use std::net::{self, IpAddr, ToSocketAddrs};
use std::{cmp, fmt, mem, ptr, str};

const BUF_ALLOC_SIZE: usize = 4096;
const MIN_VACANT_SIZE: usize = 128;
const MAX_READ_SIZE: usize = 32 * BUF_ALLOC_SIZE;

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

fn do_read_from<R: Read>(r: &mut R, v: &mut Vec<u8>) -> Result<usize, NetError> {
    let start_len = v.len();
    let capacity = v.capacity();

    if start_len == capacity {
        debug!("\t\t buffer is full.");

        return Err(NetError::from(InvalidInput));
    }

    let mut g = Guard {
        len: v.len(),
        buf: v,
    };

    unsafe {
        g.buf.set_len(capacity);
    }
    let rls = loop {
        match r.read(&mut g.buf[g.len..]) {
            Ok(n) => {
                g.len += n;
                if n == 0 {
                    debug!("\t  peer close read half");
                    break Ok(0);
                }

                if g.len == g.buf.capacity() {
                    break Ok(g.len - start_len);
                }
            }

            Err(e) => {
                break Err(NetError::from(e));
            }
        }
    };

    rls
}

struct StreamBuf {
    buf: Vec<u8>,
    pos: usize,
}

impl StreamBuf {
    pub fn new(use_buf: bool) -> StreamBuf {
        StreamBuf {
            buf: if use_buf { Vec::with_capacity(BUF_ALLOC_SIZE) } else { Vec::new() },
            pos: 0,
        }
    }

    pub fn payload_len(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn get_u8_unchecked(&self, index: usize) -> u8 {
        unsafe { *self.buf.get_unchecked(index) }
    }

    pub fn peek(&self, size: usize) -> io::Result<&[u8]> {
        if size > self.payload_len() {
            return Err(Error::from(InvalidInput));
        }

        Ok(&self.buf[self.pos..self.pos + size])
    }

    pub fn consume(&mut self, size: usize) -> io::Result<usize> {
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

    pub fn write_to(&mut self, w: &mut TcpStream) -> Result<usize, NetError> {
        if self.payload_len() == 0 {
            debug!("\t\t write_to, buffer is empty.");

            return Ok(0);
        }

        let mut write_len: usize = 0;
        let rls = loop {
            let old_paylod_len = self.payload_len();
            let result = if self.payload_len() > BUF_ALLOC_SIZE {
                w.write(&self.buf[self.pos..self.pos + BUF_ALLOC_SIZE])
            } else {
                w.write(&self.buf[self.pos..])
            };

            match result {
                Ok(n) => {
                    write_len += n;
                    self.pos += n;
                    if self.payload_len() == 0 || n == 0 {
                        if n == 0 {
                            debug!("\t\t  write to, write zero byte.");
                            if let Ok(Some(e)) = w.take_error() {
                                debug!("\t\t\t err {}", e);
                            }
                        }

                        break Ok(write_len);
                    }
                }

                Err(e) => {
                    if is_wouldblock(&e) {
                        write_len += old_paylod_len - self.payload_len();
                        debug!("\t write failed, wouldblock");
                    } else {
                        debug!("\t write failed {}", e);
                    }

                    break Err(NetError::from(e));
                }
            }
        };

        debug!("\t write {} bytes", write_len);

        if self.payload_len() == 0 {
            self.pos = 0;
            unsafe {
                self.buf.set_len(0);
            }

            let cap_len = self.buf.capacity();
            if self.buf.capacity() > BUF_ALLOC_SIZE {
                self.buf = Vec::with_capacity(BUF_ALLOC_SIZE);

                debug!(
                    "\t change buf cap len from {} to {}, resize",
                    cap_len,
                    self.buf.capacity()
                );
            }
        }


        rls
    }

    pub fn read_from<R: Read>(&mut self, r: &mut R) -> Result<usize, NetError> {
        debug!("  read from, payload {}", self.payload_len());

        let mut read_len: usize = 0;
        let rls = loop {
            if self.tail_vacant_len() < MIN_VACANT_SIZE {
                if self.head_vacant_len() > 0 {
                    self.move_payload_to_head();
                }

                if self.vacant_len() < MIN_VACANT_SIZE {
                    if self.buf.capacity() * 2 <= MAX_READ_SIZE {
                        self.buf.reserve(self.buf.capacity());
                    }

                    debug!(
                        "\t  reserve data len {}, cap len {}, reserve size {}",
                        self.payload_len(),
                        self.buf.capacity(),
                        self.buf.capacity() - self.buf.len()
                    );
                }
            }

            let old_paylod_len = self.payload_len();
            match do_read_from(r, &mut self.buf) {
                Ok(n) => {
                    read_len += n;
                    if n == 0 {
                        read_len += self.payload_len() - old_paylod_len;
                        break Ok(0);
                    }

                    if self.payload_len() >= MAX_READ_SIZE {
                        break Err(ExceedReadSize);
                    }
                }

                Err(e) => {
                    read_len += self.payload_len() - old_paylod_len;

                    if e.wouldblock() {
                        debug!("\t  wouldblock");

                        if self.payload_len() >= MAX_READ_SIZE {
                            break Err(ExceedReadSize);
                        }
                    } else {
                        debug!("\t  failed {}", e);
                    }

                    break Err(e);
                }
            }
        };

        debug!("    read {} bytes, payload {}", read_len, self.payload_len());

        rls
    }

}

pub struct Connection {
    local: Option<TcpStream>,
    local_token: Token,
    local_buf: StreamBuf,
    local_readiness: Ready,
    local_shut: Shutflag,
    local_opts: PollOpt,
    remote: Option<TcpStream>,
    remote_token: Token,
    remote_buf: StreamBuf,
    remote_readiness: Ready,
    remote_shut: Shutflag,
    remote_opts: PollOpt,
    stage: Stage,
    host: String,
}

impl Connection {
    pub fn new(use_buf: bool) -> Self {
        Connection {
            local: None,
            local_token: Token::from(std::usize::MAX),
            local_buf: StreamBuf::new(use_buf),
            local_readiness: Ready::empty(),
            local_shut: Shutflag::empty(),
            local_opts: PollOpt::empty(),
            remote: None,
            remote_token: Token::from(std::usize::MAX),
            remote_buf: StreamBuf::new(false),
            remote_readiness: Ready::empty(),
            remote_shut: Shutflag::empty(),
            remote_opts: PollOpt::empty(),
            stage: LocalConnected,
            host: "*".to_string(),
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

                if is_local_stream {
                    self.local_readiness = readiness;
                    self.local_opts = opts;
                } else {
                    self.remote_readiness = readiness;
                    self.remote_opts = opts;
                }
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
        let stream = self.get_stream(is_local_stream).unwrap();
        let token = self.get_token(is_local_stream);

        poll.reregister(stream, token, readiness, opts)
            .and_then(|_| {
                if is_local_stream {
                    self.local_readiness = readiness;
                    self.local_opts = opts;
                } else {
                    self.remote_readiness = readiness;
                    self.remote_opts = opts;
                }
                Ok(())
            })
    }

    pub fn host(&self) -> &str {
        self.host.as_str()
    }

    pub fn memory_usage(&self) -> usize {
        self.local_buf.buf.capacity() + self.remote_buf.buf.capacity()
    }

    pub fn desc(&self) -> String {
        format!(
            "({:?}, {:?}), data:({} bs, {} bs), mem:({} k, {} k), {}",
            self.local_shut,
            self.remote_shut,
            self.get_buf(LOCAL).payload_len(),
            self.get_buf(REMOTE).payload_len(),
            self.get_buf(LOCAL).buf.capacity() as f32 / 1024.0,
            self.get_buf(REMOTE).buf.capacity() as f32 / 1024.0,
            *self
        )
    }

    pub fn shutdown(&mut self, poll: &Poll, how: Shutflag, is_local_stream: bool) {
        if self.get_shutflag(is_local_stream).contains(how) {
            return;
        }

        let stream_name = if is_local_stream {
            "local"
        } else {
            "remote"
        };
        debug!("  shutdown, {} {:?} half", stream_name, how);
        let shut = if how == Shutflag::both() {
            net::Shutdown::Both
        } else if how == Shutflag::read() {
            net::Shutdown::Read
        } else if how == Shutflag::write() {
            net::Shutdown::Write
        } else {
            unreachable!()
        };

        self.insert_shutflag(how, is_local_stream);

        match shut {
            net::Shutdown::Read => {
                if let Some(stream) = self.get_stream(is_local_stream) {
                    debug!("    shutdown {} read half", stream_name);
                    let _ = stream.shutdown(net::Shutdown::Read).map_err(|e| {
                        debug!("      failed, {}", e);
                        e
                    });

                    if self.get_shutflag(is_local_stream) == Shutflag::both() {
                        debug!("    deregister {}", stream_name);
                        let _ = poll.deregister(stream).map_err(|e| {
                            debug!("      failed, {}", e);
                            e
                        });
                    }
                } else {
                    self.insert_shutflag(Shutflag::both(), is_local_stream);
                }
            }

            net::Shutdown::Write => {
                if let Some(stream) = self.get_stream(is_local_stream) {
                    debug!("    shutdown {} write half.", stream_name);
                    if self.get_buf(is_local_stream).payload_len() > 0 {
                        error!(
                            "    has {} bytes data, when shutdown write half",
                            self.get_buf(is_local_stream).payload_len()
                        );
                    }
                    let _ = stream.shutdown(net::Shutdown::Write).map_err(|e| {
                        debug!("      failed, {}", e);
                        e
                    });

                    if self.get_shutflag(is_local_stream) == Shutflag::both() {
                        debug!("    deregister {}", stream_name);
                        let _ = poll.deregister(stream).map_err(|e| {
                            debug!("      failed, {}", e);
                            e
                        });
                    }
                } else {
                    self.insert_shutflag(Shutflag::both(), is_local_stream);
                }
            }

            net::Shutdown::Both => {
                debug!("    shutdown {} both half", stream_name);
                self.insert_shutflag(Shutflag::both(), is_local_stream);
                if let Some(stream) = self.get_stream(is_local_stream) {
                    let _ = stream
                        .shutdown(net::Shutdown::Both)
                        .map_err(|e| debug!("      shutdown error: {}", e));
                    debug!("    degregister {}", stream_name);
                    let _ = poll.deregister(stream).map_err(|e| {
                        debug!("      failed, {}", e);
                        e
                    });
                }
            }
        }
    }

    pub fn get_shutflag(&self, is_local_stream: bool) -> Shutflag {
        if is_local_stream {
            self.local_shut
        } else {
            self.remote_shut
        }
    }

    fn insert_shutflag(&mut self, how: Shutflag, is_local_stream: bool) {
        if is_local_stream {
            self.local_shut |= how;
        } else {
            self.remote_shut |= how;
        }
    }
    
    fn contains_shutflag(&self, how: Shutflag, is_local_stream: bool) -> bool {
        let shut = self.get_shutflag(is_local_stream);

        shut.contains(how)
    }

    fn get_stream(&self, is_local_stream: bool) -> Option<&TcpStream> {
        if is_local_stream {
            match self.local {
                Some(ref s) => Some(&s),

                None => None,
            }
        } else {
            match self.remote {
                Some(ref s) => Some(&s),

                None => None,
            }
        }
    }

    fn get_stream_mut(&mut self, is_local_stream: bool) -> Option<&mut TcpStream> {
        if is_local_stream {
            match self.local {
                Some(ref mut s) => Some(s),

                None => None,
            }
        } else {
            match self.remote {
                Some(ref mut s) => Some(s),

                None => None,
            }
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
    
    fn get_opts(&self, is_local_stream: bool) -> PollOpt {
        if is_local_stream {
            self.local_opts
        } else {
            self.remote_opts
        }
    }

    fn insert_readiness(
        &mut self,
        poll: &Poll,
        readiness: Ready,
        is_local_stream: bool,
    ) -> io::Result<()> {
        let mut ready = self.get_readiness(is_local_stream);
        ready.insert(readiness);
        if ready != readiness {
            return self.set_readiness(poll, ready, self.get_opts(is_local_stream), is_local_stream);
        }

        Ok(())
    }

    fn remove_readiness(
        &mut self,
        poll: &Poll,
        readiness: Ready,
        is_local_stream: bool,
    ) -> io::Result<()> {
        let mut ready = self.get_readiness(is_local_stream);
        ready.remove(readiness);
        if ready != readiness {
            return self.set_readiness(poll, ready, self.get_opts(is_local_stream), is_local_stream);
        }

        Ok(())
    }

    fn set_readiness(
        &mut self,
        poll: &Poll,
        readiness: Ready,
        opts: PollOpt,
        is_local_stream: bool,
    ) -> io::Result<()> {
        if readiness == self.get_readiness(is_local_stream) && opts == self.get_opts(is_local_stream) {
            return Ok(());
        }

        let name = if is_local_stream { "local" } else { "remote" };
        debug!("\t  set {} stream readiness {:?}, {:?}", name, readiness, opts);
        self.reregister(poll, readiness, opts, is_local_stream)
    }

    pub fn ev_auth_method(&mut self, poll: &Poll) -> Result<(), (Shutflag, Shutflag)> {
        debug!("auth, @{}", *self);

        match (&mut self.local_buf).read_from(self.local.as_mut().unwrap()) {
            Ok(n) => {
                if n == 0 {
                    debug!("  read zero, close all");

                    return Err((Shutflag::both(), Shutflag::both()));
                }
            }

            Err(e) => {
                if e.wouldblock() == false {
                    debug!("  error {}, close all", e);

                    return Err((Shutflag::both(), Shutflag::both()));
                }
            }
        }

        let buf = self.get_buf(LOCAL);
        if buf.payload_len() < METHOD_SELECT_HEAD_LEN {
            warn!(
                "  recive data less than method select head len {}, close all",
                METHOD_SELECT_HEAD_LEN
            );

            return Err((Shutflag::both(), Shutflag::both()));
        }

        let head = buf.peek(METHOD_SELECT_HEAD_LEN).unwrap();
        let (ver, nmethods) = (head[0], head[1]);
        if ver != SOCKS5_VERSION {
            debug!("  invalid select head version {}", ver);

            return Err((Shutflag::both(), Shutflag::both()));
        }

        let method_sel_len = usize::from(nmethods) + METHOD_SELECT_HEAD_LEN;
        if method_sel_len > buf.payload_len() {
            warn!(
                "  recive data size {} less thhan method select len {}, close all",
                buf.payload_len(),
                method_sel_len
            );

            return Err((Shutflag::both(), Shutflag::both()));
        }

        let mut method = Method::NO_ACCEPT_METHOD;
        let sel = buf.peek(method_sel_len).unwrap();
        for pos in 0..nmethods as usize {
            if sel[METHOD_SELECT_HEAD_LEN + pos] == Method::NO_AUTH {
                method = Method::NO_AUTH;
                break;
            }
        }

        &mut self.local_buf.consume(method_sel_len);
        if method != Method::NO_AUTH {
            debug!("    {}", NetError::from(Method::NO_ACCEPT_METHOD));

            return Err((Shutflag::both(), Shutflag::both()));
        }

        let mut no_auth = [SOCKS5_VERSION; 2];
        no_auth[1] = Method::NO_AUTH;

        let rlt = self.get_stream_mut(LOCAL).unwrap().write(&no_auth);
        match rlt {
            Err(e) => {
                if is_wouldblock(&e) {
                    if let Err(e) = self.reregister(
                        poll,
                        Ready::writable(),
                        PollOpt::edge() | PollOpt::oneshot(),
                        LOCAL,
                    ) {
                        error!("  re-register LOCAL writable FAILED {}, close all", e);

                        return Err((Shutflag::both(), Shutflag::both()));
                    }

                    self.stage = SendMethodSelect;

                    return Ok(());
                }

                debug!("  write no auth responed failed {}, close all", e);

                Err((Shutflag::both(), Shutflag::both()))
            }

            Ok(_) => {
                self.stage = HandShake;

                Ok(())
            }
        }
    }

    fn ev_snd_methodsel_reply(&mut self, poll: &Poll) -> Result<(), (Shutflag, Shutflag)> {
        debug!("sel rep @{}", *self);

        if let Err(e) = self.reregister(poll, Ready::readable(), PollOpt::edge(), LOCAL) {
            error!(
                "  re-register LOCAL readable oneshot FAILED {}, close all",
                e,
            );

            return Err((Shutflag::both(), Shutflag::both()));
        }

        let no_auth = [SOCKS5_VERSION, Method::NO_AUTH];
        self.get_stream_mut(LOCAL)
            .unwrap()
            .write(&no_auth)
            .and_then(|_| {
                self.stage = HandShake;
                Ok(())
            })
            .map_err(|e| {
                debug!("  write auth response failed {}", e);

                (Shutflag::both(), Shutflag::both())
            })
    }

    fn ev_handshake(&mut self, poll: &Poll) -> Result<(), (Shutflag, Shutflag)> {
        debug!("handshake @{}", *self);

        match (&mut self.local_buf).read_from(self.local.as_mut().unwrap()) {
            Ok(n) => {
                if n == 0 {
                    debug!("  read zero bytes, close all");

                    return Err((Shutflag::both(), Shutflag::both()));
                }
            }

            Err(e) => {
                if e.wouldblock() == false {
                    debug!("  read failed {}", e);

                    return Err((Shutflag::both(), Shutflag::both()));
                }
            }
        }

        let head = self
            .local_buf
            .peek(4)
            .map_err(|_| (Shutflag::empty(), Shutflag::empty()))?;
        let (ver, cmd, _, atpy) = (head[0], head[1], head[2], head[3]);
        if ver != SOCKS5_VERSION {
            error!("  need socks version 5, recive version {}", ver);

            return Err((Shutflag::both(), Shutflag::both()));
        }

        let addr: String;
        let port: u16;
        match atpy {
            AddrType::V4 => {
                if self.local_buf.payload_len() < CMD_IPV4_LEN {
                    debug!("    ipv4, need {} bytes at least, but only {} bytes recived, need more data.", CMD_IPV4_LEN, self.local_buf.payload_len());

                    return Err((Shutflag::both(), Shutflag::both()));
                }

                let bs = self.local_buf.peek(CMD_IPV4_LEN).unwrap();
                addr = net::Ipv4Addr::new(
                    bs[CMD_HEAD_LEN],
                    bs[CMD_HEAD_LEN + 1],
                    bs[CMD_HEAD_LEN + 2],
                    bs[CMD_HEAD_LEN + 3],
                )
                .to_string();
                port = unsafe { u16::from_be(mem::transmute::<[u8; 2], u16>([bs[8], bs[9]])) };

                debug!("    ipv4 {}:{}", addr, port);

                (&mut self.local_buf).consume(CMD_IPV4_LEN).unwrap();
            }

            AddrType::DOMAIN => {
                if self.local_buf.payload_len() < CMD_HEAD_LEN + 1 {
                    debug!(
                        "     domain head len {}, but payload len {}, need more data, close all",
                        CMD_HEAD_LEN,
                        self.local_buf.payload_len(),
                    );

                    return Err((Shutflag::both(), Shutflag::both()));
                }

                let domain_len = usize::from(self.local_buf.get_u8_unchecked(CMD_HEAD_LEN));
                let total_len = CMD_HEAD_LEN + 1 + domain_len + 2;
                if self.local_buf.payload_len() < total_len {
                    debug!(
                        "    domain total len {}, but payload len {}, need more data, close all",
                        total_len,
                        self.local_buf.payload_len(),
                    );

                    return Err((Shutflag::both(), Shutflag::both()));
                }

                let bs = self.local_buf.peek(total_len).unwrap();
                addr = str::from_utf8(&bs[CMD_HEAD_LEN + 1..total_len - 2])
                    .unwrap()
                    .to_string();
                port = unsafe {
                    u16::from_be(mem::transmute::<[u8; 2], u16>([
                        bs[total_len - 2],
                        bs[total_len - 1],
                    ]))
                };

                debug!("    domain {}:{}", addr, port);

                (&mut self.local_buf).consume(total_len).unwrap();
            }

            AddrType::V6 => {
                if self.local_buf.payload_len() < CMD_IPV6_LEN {
                    debug!("    ipv6, head need {} bytes at least, but only {} bytes recived, need more data, close all", CMD_IPV6_LEN, self.local_buf.payload_len());

                    return Err((Shutflag::both(), Shutflag::both()));
                }

                let bs = self.local_buf.peek(CMD_IPV6_LEN).unwrap();
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

                debug!("    ipv6 {}:{}", addr, port);

                self.local_buf.consume(CMD_IPV6_LEN).unwrap();
            }

            _ => {
                let response = [SOCKS5_VERSION, ADDRTYPE_NOT_SUPPORTED, 0, V4];
                error!("    not supported addrtype {}", atpy);
                if let Err(e) = self.get_stream_mut(LOCAL).unwrap().write(&response) {
                    warn!("    write ADDRTYPE_NOT_SUPPORTED failed: {}", e);
                }

                return Err((Shutflag::both(), Shutflag::both()));
            }
        }

        match cmd {
            Cmd::CONNECT => {
                self.host = format!("{}:{}", addr, port);
                debug!("    connect, host {}", self.host);

                let addrs_result = self.host.to_socket_addrs();
                if let Err(e) = addrs_result {
                    error!("    resolve host failed {}", e);

                    return Err((Shutflag::both(), Shutflag::both()));
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
                            error!("  register remote connection failed: {}", e);

                            return Err(e);
                        }

                        self.stage = RemoteConnecting;

                        Ok(())
                    })
                    .map_err(|e| {
                        error!("  connect failed {}", e);

                        // Prevent calling shutdown
                        self.insert_shutflag(Shutflag::both(), REMOTE);

                        (Shutflag::both(), Shutflag::both())
                    })
            }

            _ => {
                let response = [SOCKS5_VERSION, CMD_NOT_SUPPORTED, 0, V4];
                self.get_stream_mut(LOCAL)
                    .unwrap()
                    .write(&response)
                    .unwrap();

                error!(
                    "    not supported command {}",
                    NetError::from(CMD_NOT_SUPPORTED)
                );

                return Err((Shutflag::both(), Shutflag::both()));
            }
        }
    }

    fn ev_nonblock_connected(
        &mut self,
        poll: &Poll,
        ev: &mio::Event,
    ) -> Result<(), (Shutflag, Shutflag)> {
        debug!("triger remote connected event @{}", *self);

        assert_eq!(self.get_token(REMOTE), ev.token());

        self.remote
            .as_ref()
            .unwrap()
            .take_error()
            .and_then(|option| {
                if let Some(e) = option {
                    debug!("  connected FAILED {}", e);

                    let response = [SOCKS5_VERSION, HOST_UNREACHABLE, 0, V4];
                    let _ = self.get_stream(LOCAL).unwrap().write(&response);

                    Err(e)
                } else {
                    Ok(())
                }
            })
            .map_err(|e| {
                debug!("  non-block connect return error {}, close all", e);

                // Prevent calling shutdown
                self.insert_shutflag(Shutflag::both(), REMOTE);

                (Shutflag::both(), Shutflag::both())
            })?;

        let sock_addr = self.get_stream(REMOTE).unwrap().local_addr().unwrap();
        let port = sock_addr.port();
        let write_result;
        match sock_addr.ip() {
            IpAddr::V4(addr) => {
                let mut response = [SOCKS5_VERSION, SUCCEEDED, 0, V4, 0, 0, 0, 0, 0, 0];
                &mut response[4..8].copy_from_slice(&addr.octets());

                let bs: [u8; 2] = unsafe { mem::transmute::<u16, [u8; 2]>(port.to_be()) };
                &mut response[8..].copy_from_slice(&bs);
                write_result = self.get_stream_mut(LOCAL).unwrap().write(&response);
            }

            IpAddr::V6(addr) => {
                let mut response = [SOCKS5_VERSION; 22];
                response[1] = SUCCEEDED;
                response[2] = 0;
                response[3] = V6;
                &mut response[4..20].copy_from_slice(&addr.octets());
                response[20] = (port.to_be() >> 1) as u8;
                response[21] = (port.to_be() & 0xff) as u8;
                write_result = self.get_stream_mut(LOCAL).unwrap().write(&response);
            }
        }

        if let Err(e) = write_result {
            debug!("  write connect response failed {}, close all", e);

            return Err((Shutflag::both(), Shutflag::both()));
        }

        let _ = self.set_readiness(poll, Ready::readable(), PollOpt::edge(), REMOTE);
        self.remote_buf.buf = Vec::with_capacity(BUF_ALLOC_SIZE);
        self.stage = Streaming;

        Ok(())
    }

    fn ev_streaming(&mut self, poll: &Poll, ev: &mio::Event) -> Result<(), (Shutflag, Shutflag)> {
        let token = ev.token();
        if ev.readiness().is_readable() {
            if token == self.get_token(LOCAL) {
                debug!("streaming, local readable, @{}", *self);

                let rls = (&mut self.remote_buf).read_from(self.local.as_mut().unwrap());
                match rls {
                    Ok(n) => {
                        if n == 0 {
                            if self.remote_buf.payload_len() > 0 {
                                let _ = self.set_readiness(poll, Ready::writable(), PollOpt::edge(), REMOTE);

                                return Err((Shutflag::both(), Shutflag::read()));
                            } else {
                                return Err((Shutflag::both(), Shutflag::both()));
                            }
                        } else {
                            let _ = self.insert_readiness(poll, Ready::writable(), REMOTE);
                        }
                    }

                    Err(ExceedReadSize) => {
                        let _ = self.set_readiness(poll, Ready::empty(), PollOpt::edge(), LOCAL);
                        let _ = self.insert_readiness(poll, Ready::writable(), REMOTE);
                    },

                    Err(e) => {
                        if e.wouldblock() == false {
                            debug!("    copy local to remote with error {}", e);

                            return Err((Shutflag::both(), Shutflag::both()));
                        }

                        if self.remote_buf.payload_len() > 0 {
                            let _ = self.insert_readiness(poll, Ready::writable(), REMOTE);
                        }
                    }
                }
            } else if token == self.get_token(REMOTE) {
                debug!("streaming, remote readable, @{}", *self);

                let rls = (&mut self.local_buf).read_from(self.remote.as_mut().unwrap());
                match rls {
                    Ok(n) => {
                        if n == 0 {
                            if self.local_buf.payload_len() > 0 {
                                let _ = self.set_readiness(poll, Ready::writable(), PollOpt::edge(), LOCAL);

                                return Err((Shutflag::read(), Shutflag::both()));
                            } else {
                                return Err((Shutflag::both(), Shutflag::both()));
                            }
                        } else {
                            let _ = self.insert_readiness(poll, Ready::writable(), LOCAL);
                        }
                    },

                    Err(ExceedReadSize) => {
                        let _ = self.set_readiness(poll, Ready::empty(), PollOpt::edge(), REMOTE);
                        let _ = self.insert_readiness(poll, Ready::writable(), LOCAL);
                    },

                    Err(e) => {
                        if e.wouldblock() == false {
                            debug!("    read remote to local buf failed, {}", e);

                            return Err((Shutflag::both(), Shutflag::both()));
                        }

                        if self.local_buf.payload_len() > 0 {
                            let _ = self.insert_readiness(poll, Ready::writable(), LOCAL);
                        }
                    }
                }
            } else {
                unreachable!();
            }
        } else if ev.readiness().is_writable() {
            if token == self.get_token(LOCAL) {
                debug!(
                    "streaming, local writable, payload len {}, @{}",
                    self.local_buf.payload_len(),
                    *self
                );

                let rls = (&mut self.local_buf).write_to(self.local.as_mut().unwrap());
                match rls {
                    Ok(_) => {
                        if self.local_buf.payload_len() == 0 {
                            let _ = self.remove_readiness(poll, Ready::writable(), LOCAL);

                            if self.contains_shutflag(Shutflag::read(), REMOTE) {
                                debug!("  shut flag (write, empty)");
                                return Err((Shutflag::write(), Shutflag::empty()));
                            }

                            if self.get_readiness(REMOTE) == Ready::empty() {
                                let _ = self.set_readiness(poll, Ready::readable(), PollOpt::level(), REMOTE);
                            } else {
                                let _ = self.set_readiness(poll, Ready::readable(), PollOpt::edge(), REMOTE);
                            }
                        }
                    }

                    Err(e) => {
                        if e.wouldblock() == false {
                            debug!(
                                "    local stream write failed, error: {}, close all.",
                                e
                            );

                            return Err((Shutflag::both(), Shutflag::both()));
                        }
                    }
                }
            } else if token == self.get_token(REMOTE) {
                debug!(
                    "streaming, remote writable, payload len {}, @{}",
                    self.remote_buf.payload_len(),
                    *self
                );

                let rls = (&mut self.remote_buf).write_to(self.remote.as_mut().unwrap());
                match rls {
                    Ok(_) => {
                        if self.remote_buf.payload_len() == 0 {
                            let _ = self.remove_readiness(poll, Ready::writable(), REMOTE);

                            if self.contains_shutflag(Shutflag::read(), LOCAL) {
                                debug!("  shut flag (write, empty)");
                                return Err((Shutflag::empty(), Shutflag::write()));
                            }

                            if self.get_readiness(LOCAL) == Ready::empty() {
                                let _ = self.set_readiness(poll, Ready::readable(), PollOpt::level(), LOCAL);
                            } else {
                                let _ = self.set_readiness(poll, Ready::readable(), PollOpt::edge(), LOCAL);
                            }
                        }
                    }

                    Err(e) => {
                        if e.wouldblock() == false {
                            debug!(
                                "    local stream write failed, error: {}, close all.",
                                e
                            );

                            return Err((Shutflag::both(), Shutflag::both()));
                        }
                    }
                }
            } else {
                unreachable!();
            }
        }

        Ok(())
    }

    pub fn handle_events(
        &mut self,
        poll: &Poll,
        ev: &mio::Event,
    ) -> Result<(), (Shutflag, Shutflag)> {
        let rlt = match self.stage {
            LocalConnected => self.ev_auth_method(poll),

            SendMethodSelect => self.ev_snd_methodsel_reply(poll),

            HandShake => self.ev_handshake(poll),

            RemoteConnecting => self.ev_nonblock_connected(poll, ev),

            Streaming => self.ev_streaming(poll, ev),
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
