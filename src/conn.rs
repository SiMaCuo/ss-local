use super::err::*;
use super::shut::*;
use super::socks5::{AddrType::*, Rep::*, Stage::*, *};
use log::{debug, error, warn};
use mio::{self, net::TcpStream, Poll, PollOpt, Ready, Token};
use std::io::{self, Error, ErrorKind::*, Read, Write};
use std::net::{self, IpAddr, ToSocketAddrs};
use std::{cmp, fmt, mem, ptr, str};

const BUF_ALLOC_SIZE: usize = 4096;
const MAX_RDWD_SIZE: usize = 4 * BUF_ALLOC_SIZE;
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
        debug!("\t\t buffer is full.");

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

    pub fn write_to(&mut self, w: &mut TcpStream) -> io::Result<usize> {
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
                    if self.payload_len() == 0 || n == 0 {
                        if n == 0 {
                            debug!("\t\t  write_to, write zero byte.");
                            if let Ok(Some(e)) = w.take_error() {
                                debug!("\t\t\t err {}", e);
                            }
                        }
                        break Ok(total_write_len);
                    }
                }

                Err(e) => {
                    debug!("\t\t  write_to, {}", e);
                    if total_write_len > 0 {
                        break Ok(total_write_len);
                    } else {
                        break Err(e);
                    }
                }
            }
        };

        if self.payload_len() == 0 {
            self.pos = 0;
            unsafe {
                self.buf.set_len(0);
            }

            let cap_len = self.buf.capacity();
            if self.buf.capacity() > 2 * BUF_ALLOC_SIZE {
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

    pub fn read_from<R: Read>(&mut self, r: &mut R) -> io::Result<usize> {
        if self.vacant_len() < MIN_VACANT_SIZE {
            if self.head_vacant_len() > 0 {
                self.move_payload_to_head();
            }

            self.buf.reserve(BUF_ALLOC_SIZE);
            debug!(
                "  read_from, reserve space data len {}, capacity {}",
                self.buf.len(),
                self.buf.capacity()
            );
        }

        do_read_from(r, &mut self.buf)
    }

    pub fn copy(&mut self, r: &mut TcpStream, w: &mut TcpStream) -> io::Result<usize> {
        debug!("  copying...., payload {} bytes", self.payload_len());
        let mut wd_len: usize = 0;
        let mut rd_len: usize = 0;
        let mut wd_wouldblk: bool = false;

        if self.payload_len() > 0 {
            if let Ok(n) = self.write_to(w) {
                wd_len += n;
            }

            debug!("    write len {} ", wd_len);
        }

        if self.payload_len() > MAX_RDWD_SIZE {
            return Err(Error::from(Other));
        }

        let rls = loop {
            let payload_befor_rd = self.payload_len();
            match self.read_from(r) {
                Ok(n) => {
                    rd_len += n;
                    if self.payload_len() > 0 && wd_len < MAX_RDWD_SIZE && wd_wouldblk == false {
                        match self.write_to(w) {
                            Ok(n) => {
                                wd_len += n;
                            }

                            Err(e) => {
                                if is_wouldblock(&e) {
                                    debug!("\t write to target would block.");

                                    wd_wouldblk = true;
                                }
                            }
                        }
                    }

                    if n == 0 {
                        break Ok(rd_len);
                    }
                }

                Err(e) => {
                    if is_wouldblock(&e) == false {
                        debug!("\t read error {}", e);

                        break Err(e);
                    }
                    rd_len += self.payload_len() - payload_befor_rd;
                    if wd_len < MAX_RDWD_SIZE && self.payload_len() > 0 {
                        if let Ok(n) = self.write_to(w) {
                            wd_len += n;
                        }
                    }

                    if rd_len > 0 {
                        break Ok(rd_len);
                    }
                }
            }

            if rd_len + wd_len >= 3 * MAX_RDWD_SIZE {
                debug!("\t\t out range: rd_len {}, wd_len {}", rd_len, wd_len);
                break Err(Error::from(Other));
            }
        };

        debug!(
            "\t copy, read {} bytes, write {} bytes, data len {}, buf capacity {} bytes, {:?}",
            rd_len,
            wd_len,
            self.buf.len(),
            self.buf.capacity(),
            rls
        );

        rls
    }
}

pub struct Connection {
    local: Option<TcpStream>,
    local_token: Token,
    local_buf: StreamBuf,
    local_readiness: Ready,
    local_shut: Shutflag,
    remote: Option<TcpStream>,
    host: String,
    remote_token: Token,
    remote_buf: StreamBuf,
    remote_readiness: Ready,
    remote_shut: Shutflag,
    stage: Stage,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            local: None,
            local_token: Token::from(std::usize::MAX),
            local_buf: StreamBuf::new(),
            local_readiness: Ready::empty(),
            local_shut: Shutflag::empty(),
            remote: None,
            host: "*".to_string(),
            remote_token: Token::from(std::usize::MAX),
            remote_buf: StreamBuf::new(),
            remote_readiness: Ready::empty(),
            remote_shut: Shutflag::empty(),
            stage: LocalConnected,
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
        let stream = self.get_stream(is_local_stream).unwrap();
        let token = self.get_token(is_local_stream);

        poll.reregister(stream, token, readiness, opts)
            .and_then(|_| {
                self.set_readiness(readiness, is_local_stream);

                Ok(())
            })
    }

    pub fn host(&self) -> &str {
        self.host.as_str()
    }

    pub fn memory_usage(&self) -> usize {
        self.local_buf.buf.capacity() + self.remote_buf.buf.capacity()
    }

    pub fn shutdown(&mut self, poll: &Poll, how: Shutflag, is_local_stream: bool) {
        if self.get_shutflag(is_local_stream).contains(how) {
            return;
        }

        let (stream_name, peer_name) = if is_local_stream {
            ("local", "remote")
        } else {
            ("remote", "local")
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

                    if self.get_buf(!is_local_stream).payload_len() == 0 {
                        self.insert_shutflag(Shutflag::write(), !is_local_stream);
                    }

                    match self.get_stream(!is_local_stream) {
                        Some(peer) => {
                            if self.get_buf(!is_local_stream).payload_len() == 0 {
                                debug!("    shutdown {} write half", peer_name);
                                let _ = peer.shutdown(net::Shutdown::Write).map_err(|e| {
                                    debug!("      failed, {}", e);
                                    e
                                });
                                if self.get_shutflag(!is_local_stream) == Shutflag::both() {
                                    debug!("    deregister {}", peer_name);
                                    let _ = poll.deregister(peer).map_err(|e| {
                                        debug!("      failed, {}", e);
                                        e
                                    });
                                }
                            }
                        }

                        None => self.insert_shutflag(Shutflag::both(), !is_local_stream),
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

                    match self.get_stream(!is_local_stream) {
                        Some(peer) => {
                            debug!("    shutdown {} read half", peer_name);
                            let _ = peer.shutdown(net::Shutdown::Read).map_err(|e| {
                                debug!("      failed, {}", e);
                                e
                            });
                            if self.get_shutflag(!is_local_stream) == Shutflag::both() {
                                debug!("    deregister {}", peer_name);
                                let _ = poll.deregister(peer).map_err(|e| {
                                    debug!("      failed, {}", e);
                                    e
                                });
                            }
                        }

                        None => self.insert_shutflag(Shutflag::both(), !is_local_stream),
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
                    let _ = poll.deregister(stream).map_err(|e| {
                        debug!("      failed, {}", e);
                        e
                    });
                }

                match self.get_stream(!is_local_stream) {
                    Some(peer) => {
                        if self.get_buf(!is_local_stream).payload_len() > 0 {
                            debug!("    shutdown {} read half", peer_name);
                            let _ = peer.shutdown(net::Shutdown::Read).map_err(|e| {
                                debug!("      failed, {}", e);
                                e
                            });
                            self.insert_shutflag(Shutflag::read(), !is_local_stream);
                        } else {
                            if self
                                .get_shutflag(!is_local_stream)
                                .contains(Shutflag::read())
                                == false
                            {
                                debug!("    shutdown {} read half", peer_name);
                                let _ = peer.shutdown(net::Shutdown::Read).map_err(|e| {
                                    debug!("      failed, {}", e);
                                    e
                                });
                            }
                            if self
                                .get_shutflag(!is_local_stream)
                                .contains(Shutflag::write())
                                == false
                            {
                                debug!("    shutdown {} write half", peer_name);
                                let _ = peer.shutdown(net::Shutdown::Write).map_err(|e| {
                                    debug!("      failed, {}", e);
                                    e
                                });
                            }
                            self.insert_shutflag(Shutflag::both(), !is_local_stream);
                        }
                    }

                    None => self.insert_shutflag(Shutflag::both(), !is_local_stream),
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

    fn set_readiness(&mut self, readiness: Ready, is_local_stream: bool) {
        if is_local_stream {
            self.local_readiness = readiness;
        } else {
            self.remote_readiness = readiness;
        }
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
                if is_wouldblock(&e) == false {
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
            debug!("    {}", CliError::from(Method::NO_ACCEPT_METHOD));

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
                if is_wouldblock(&e) == false {
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
                    CliError::from(CMD_NOT_SUPPORTED)
                );

                return Err((Shutflag::both(), Shutflag::both()));
            }
        }
    }

    fn ev_nonblock_connected(
        &mut self,
        _poll: &Poll,
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

        self.stage = Streaming;

        Ok(())
    }

    fn ev_streaming(&mut self, poll: &Poll, ev: &mio::Event) -> Result<(), (Shutflag, Shutflag)> {
        let token = ev.token();
        if ev.readiness().is_readable() {
            if token == self.get_token(LOCAL) {
                debug!("streaming, local readable, @{}", *self);

                let mut rd: usize = usize::max_value();
                let rls = (&mut self.remote_buf)
                    .copy(self.local.as_mut().unwrap(), self.remote.as_mut().unwrap());
                match rls {
                    Ok(n) => {
                        rd = n;
                    }

                    Err(e) => {
                        if e.kind() == Other {
                            debug!("  re-register local readable, level trigger");
                            let _ =
                                self.reregister(poll, Ready::readable(), PollOpt::level(), LOCAL);
                        }

                        if is_wouldblock(&e) == false {
                            debug!("    copy local to remote with error {}", e);

                            return Err((Shutflag::both(), Shutflag::both()));
                        }
                    }
                }

                let mut readiness = Ready::readable();
                if self.remote_buf.payload_len() > 0 {
                    readiness |= Ready::writable();
                }

                if readiness != self.get_readiness(REMOTE) {
                    debug!("    change remote sock readiness {:?}", readiness);

                    if let Err(e) = self.reregister(poll, readiness, PollOpt::edge(), REMOTE) {
                        error!("      failed {}", e);

                        return Err((Shutflag::both(), Shutflag::both()));
                    }
                }

                if rd == 0 {
                    if readiness.contains(Ready::writable()) {
                        return Err((Shutflag::read(), Shutflag::empty()));
                    } else {
                        return Err((Shutflag::read(), Shutflag::write()));
                    }
                }
            } else if token == self.get_token(REMOTE) {
                debug!("streaming, remote readable, @{}", *self);

                let mut rd: usize = usize::max_value();
                let rls = (&mut self.local_buf)
                    .copy(self.remote.as_mut().unwrap(), self.local.as_mut().unwrap());
                match rls {
                    Ok(n) => {
                        rd = n;
                    }

                    Err(e) => {
                        if e.kind() == Other {
                            debug!("  re-register remote readable, level trigger");
                            let _ =
                                self.reregister(poll, Ready::readable(), PollOpt::level(), REMOTE);
                        } else if is_wouldblock(&e) == false {
                            debug!("    copy remote to local with error {}", e);

                            return Err((Shutflag::both(), Shutflag::both()));
                        }
                    }
                }

                let mut readiness = Ready::readable();
                if self.local_buf.payload_len() > 0 {
                    readiness |= Ready::writable();
                }

                if readiness != self.get_readiness(LOCAL) {
                    debug!("    change local sock readiness {:?}", readiness);

                    if let Err(e) = self.reregister(poll, readiness, PollOpt::edge(), LOCAL) {
                        error!("      failed {}", e);

                        return Err((Shutflag::both(), Shutflag::both()));
                    }
                }

                if rd == 0 {
                    if readiness.contains(Ready::writable()) {
                        return Err((Shutflag::empty(), Shutflag::read()));
                    } else {
                        return Err((Shutflag::write(), Shutflag::read()));
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

                while self.local_buf.payload_len() > 0 {
                    let rls = (&mut self.local_buf).write_to(self.local.as_mut().unwrap());
                    match rls {
                        Ok(n) => {
                            if n == 0 {
                                break;
                            }
                        }

                        Err(e) => {
                            if is_wouldblock(&e) {
                                break;
                            }

                            debug!("    write local buf to local stream failed, error: {}, shutdown all.", e);

                            return Err((Shutflag::both(), Shutflag::both()));
                        }
                    }
                }

                debug!(
                    "    local buf residue {} bytes",
                    self.local_buf.payload_len()
                );

                let mut readiness = if self.get_shutflag(LOCAL).contains(Shutflag::read()) {
                    Ready::empty()
                } else {
                    Ready::readable()
                };

                readiness |= if self.local_buf.payload_len() > 0 {
                    Ready::writable()
                } else {
                    Ready::empty()
                };

                debug!("    re-register local readiness {:?}", readiness);
                if let Err(e) = self.reregister(poll, readiness, PollOpt::edge(), LOCAL) {
                    debug!("      failed, {}", e);

                    return Err((Shutflag::both(), Shutflag::both()));
                }
            } else if token == self.get_token(REMOTE) {
                debug!(
                    "streaming, remote writable, payload len {}, @{}",
                    self.remote_buf.payload_len(),
                    *self
                );

                while self.remote_buf.payload_len() > 0 {
                    let rls = (&mut self.remote_buf).write_to(self.remote.as_mut().unwrap());
                    match rls {
                        Ok(n) => {
                            if n == 0 {
                                break;
                            }
                        }

                        Err(e) => {
                            if is_wouldblock(&e) {
                                break;
                            }

                            debug!("    write remote buf to remote stream failed, error: {}, shutdown all.", e);

                            return Err((Shutflag::both(), Shutflag::both()));
                        }
                    }
                }

                debug!(
                    "    remote buf residue {} bytes",
                    self.remote_buf.payload_len()
                );

                let mut readiness = if self.get_shutflag(REMOTE).contains(Shutflag::read()) {
                    Ready::empty()
                } else {
                    Ready::readable()
                };

                readiness |= if self.remote_buf.payload_len() > 0 {
                    Ready::writable()
                } else {
                    Ready::empty()
                };

                debug!("    re-register remote readiness {:?}", readiness);
                if let Err(e) = self.reregister(poll, readiness, PollOpt::edge(), REMOTE) {
                    debug!("      failed, {}", e);

                    return Err((Shutflag::both(), Shutflag::both()));
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
