use bytes::{Buf, Bytes, BytesMut};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use std::{
    fmt::{self, Debug, Formatter},
    future::Future,
    io::{self, Cursor, Error, ErrorKind},
    net::{self, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    task::{LocalWaker, Poll},
};

pub const CMD_HEAD_LEN: usize = 4;
pub const CMD_IPV4_LEN: usize = CMD_HEAD_LEN + 4 + 2;
pub const CMD_IPV6_LEN: usize = CMD_HEAD_LEN + 16 + 2;
pub const METHOD_SELECT_HEAD_LEN: usize = 2;

pub const SOCKS5_VERSION: u8 = 5;
#[cfg_attr(rustfmt, rustfmt_skip)]
mod S5Code {
    pub const SOCKS5_METHOD_NO_AUTH: u8                 = 0x0;
    pub const SOCKS5_METHOD_GSSAPI: u8                  = 0x1;
    pub const SOCKS5_METHOD_NAME_PASSWORD: u8           = 0x3;
    pub const SOCKS5_METHOD_NO_ACCEPT: u8               = 0xff;
    pub const SOCKS5_COMMAND_CONNECT: u8                = 0x1;
    pub const SOCKS5_COMMAND_BIND: u8                   = 0x2;
    pub const SOCKS5_COMMAND_UDP_ASSOCIATE: u8          = 0x3;
    pub const SOCKS5_ADDRTYPE_V4: u8                    = 0x01;
    pub const SOCKS5_ADDRTYPE_DOMAIN: u8                = 0x03;
    pub const SOCKS5_ADDRTYPE_V6: u8                    = 0x04;
    pub const SOCKS5_REPLY_SUCCEEDED: u8                = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE: u8          = 0x01;
    pub const SOCKS5_REPLY_CONNECT_DISALLOWED: u8       = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8      = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE: u8         = 0x04;
    pub const SOCKS5_REPLY_CONNECT_REFUSED: u8          = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED: u8              = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8    = 0x07;
    pub const SOCKS5_REPLY_ADDRTYPE_NOT_SUPPORTED: u8   = 0x08;
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Stage {
    LocalConnected,
    SendMethodSelect,
    HandShake,
    RemoteConnecting,
    Streaming,
}

#[derive(Clone, Debug, Copy)]
enum Method {
    NoAuth,
    GssApi,
    NamePassword,
    NoAcceptMethod,
}

impl Method {
    fn as_u8(self) -> u8 {
        match self {
            Method::NoAuth => S5Code::SOCKS5_METHOD_NO_AUTH,
            Method::GssApi => S5Code::SOCKS5_METHOD_GSSAPI,
            Method::NamePassword => S5Code::SOCKS5_METHOD_NAME_PASSWORD,
            Method::NoAcceptMethod => S5Code::SOCKS5_METHOD_NO_ACCEPT,
        }
    }

    fn from_u8(code: u8) -> Option<Method> {
        match code {
            S5Code::SOCKS5_METHOD_NO_AUTH => Some(Method::NoAuth),
            S5Code::SOCKS5_METHOD_GSSAPI => Some(Method::GssApi),
            S5Code::SOCKS5_METHOD_NAME_PASSWORD => Some(Method::NamePassword),
            S5Code::SOCKS5_METHOD_NO_ACCEPT => Some(Method::NoAcceptMethod),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Copy)]
enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Command {
    fn as_u8(self) -> u8 {
        match self {
            Command::Connect => S5Code::SOCKS5_COMMAND_CONNECT,
            Command::Bind => S5Code::SOCKS5_COMMAND_BIND,
            Command::UdpAssociate => S5Code::SOCKS5_COMMAND_UDP_ASSOCIATE,
        }
    }

    fn from_u8(code: u8) -> Option<Command> {
        match code {
            S5Code::SOCKS5_COMMAND_CONNECT => Some(Command::Connect),
            S5Code::SOCKS5_COMMAND_BIND => Some(Command::Bind),
            S5Code::SOCKS5_COMMAND_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Copy)]
enum AddrType {
    V4,
    Domain,
    V6,
}

impl AddrType {
    fn as_u8(self) -> u8 {
        match self {
            AddrType::V4 => S5Code::SOCKS5_ADDRTYPE_V4,
            AddrType::Domain => S5Code::SOCKS5_ADDRTYPE_DOMAIN,
            AddrType::V6 => S5Code::SOCKS5_ADDRTYPE_V6,
        }
    }

    fn from_u8(code: u8) -> AddrType {
        match code {
            S5Code::SOCKS5_ADDRTYPE_V4 => AddrType::V4,
            S5Code::SOCKS5_ADDRTYPE_DOMAIN => AddrType::Domain,
            S5Code::SOCKS5_ADDRTYPE_V6 => AddrType::V6,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, Copy)]
enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectDisallowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectRefused,
    TtlExpired,
    CommandNotSupported,
    AddrtypeNotSupported,
}

impl Reply {
    fn as_u8(self) -> u8 {
        match self {
            Reply::Succeeded => S5Code::SOCKS5_REPLY_SUCCEEDED,
            Reply::GeneralFailure => S5Code::SOCKS5_REPLY_GENERAL_FAILURE,
            Reply::ConnectDisallowed => S5Code::SOCKS5_REPLY_CONNECT_DISALLOWED,
            Reply::NetworkUnreachable => S5Code::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Reply::HostUnreachable => S5Code::SOCKS5_REPLY_HOST_UNREACHABLE,
            Reply::ConnectRefused => S5Code::SOCKS5_REPLY_CONNECT_REFUSED,
            Reply::TtlExpired => S5Code::SOCKS5_REPLY_TTL_EXPIRED,
            Reply::CommandNotSupported => S5Code::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Reply::AddrtypeNotSupported => S5Code::SOCKS5_REPLY_ADDRTYPE_NOT_SUPPORTED,
        }
    }

    fn from_u8(code: u8) -> Option<Reply> {
        match code {
            S5Code::SOCKS5_REPLY_SUCCEEDED => Some(Reply::Succeeded),
            S5Code::SOCKS5_REPLY_GENERAL_FAILURE => Some(Reply::GeneralFailure),
            S5Code::SOCKS5_REPLY_CONNECT_DISALLOWED => Some(Reply::ConnectDisallowed),
            S5Code::SOCKS5_REPLY_NETWORK_UNREACHABLE => Some(Reply::NetworkUnreachable),
            S5Code::SOCKS5_REPLY_HOST_UNREACHABLE => Some(Reply::HostUnreachable),
            S5Code::SOCKS5_REPLY_CONNECT_REFUSED => Some(Reply::ConnectRefused),
            S5Code::SOCKS5_REPLY_TTL_EXPIRED => Some(Reply::TtlExpired),
            S5Code::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => Some(Reply::CommandNotSupported),
            S5Code::SOCKS5_REPLY_ADDRTYPE_NOT_SUPPORTED => Some(Reply::AddrtypeNotSupported),
            _ => None,
        }
    }
}

fn get_address_len(atyp: &Address) -> usize {
    match atyp {
        Address::SocketAddr(net::SocketAddr::V4(..)) => 1 + 4 + 2,
        Address::SocketAddr(net::SocketAddr::V6(..)) => 1 + 16 + 2,
        Address::DomainName(ref dmname, _) => 1 + 1 + dmname.len() + 2,
    }
}

#[derive(Clone)]
pub enum Address {
    SocketAddr(net::SocketAddr),
    DomainName(String, u16),
}

impl Debug for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Address::SocketAddr(ref addr) => write!(f, "{}", addr),
            Address::DomainName(ref dmname, ref port) => write!(f, "{}:{}", dmname, port),
        }
    }
}

#[derive(Debug)]
enum ReadAddressState {
    ReadAddrType,
    ReadIpV4,
    ReadIpV6,
    ReadDomain,
}

pub struct ReadAddress<R>
where
    R: AsyncReadExt,
{
    state: ReadAddressState,
    reader: Option<R>,
    buf: Option<BytesMut>,
    read_len: usize,
}

impl<R> ReadAddress<R>
where
    R: AsyncReadExt,
{
    fn new(r: R) -> ReadAddress<R> {
        ReadAddress {
            state: ReadAddressState::ReadAddrType,
            reader: Some(r),
            buf: None,
            read_len: 0,
        }
    }

    fn read_addr_type(&mut self) -> io::Result<AddrType> {
        let atyp = self.reader.as_mut().unwrap().read_u8()?;
        match AddrType::from_u8(atyp) {
            AddrType::V4 => {
                self.state = ReadAddressState::ReadIpV4;
                self.alloc_buf(4 + 2);
            }
            AddrType::V6 => {
                self.state = ReadAddressState::ReadIpV6;
                self.alloc_buf(16 + 2);
            }
            AddrType::Domain => {
                let dm_len = self.reader.as_mut().unwrap().read_u8()?;
                self.state = ReadAddressState::ReadDomain;
                self.alloc_buf(dm_len + 2);
            }
        }

        Ok(AddrType::from_u8(atyp))
    }

    fn alloc_buf(&mut self, size: usize) {
        let mut buf = BytesMut::with_capacity(size);
        unsafe {
            buf.set_len(size);
        }

        self.buf = Some(buf);
    }

    fn read_data(&mut self) -> Poll<io::Result<()>> {
        debug_assert!(self.buf.is_some());

        let buf = self.buf.as_mut().unwrap();
        match self
            .reader
            .as_mut()
            .unwrap()
            .read(&mut buf[self.read_len..])
        {
            Ok(0) => {
                return Poll::Ready(Err(Error::from(ErrorKind::UnexpectedEof)));
            }

            Ok(n) => {
                self.read_len += n;
                if self.read_len < buf.len() {
                    return Poll::Pending;
                }
            }

            Err(e) => {
                if e.kind() == ErrorKind::UnexpectedEof || e.kind() == ErrorKind::Interrupted {
                    return Poll::Pending;
                } else {
                    return Poll::Ready(Err(e.into()));
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<R> Future for ReadAddress<R>
where
    R: AsyncReadExt,
{
    type Output = io::Result<(R, Address)>;

    fn poll(self: Pin<&mut Self>, lw: &LocalWaker) -> Poll<Self::Output> {
        debug_assert!(self.reader.is_some());
    }
}
