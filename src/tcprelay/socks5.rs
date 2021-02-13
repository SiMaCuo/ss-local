use bytes::Buf;
use smol::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{self, TcpStream, IpAddr, Ipv4Addr, Ipv6Addr},
};
use std::{
    fmt::{self, Debug, Formatter},
    io::{self, Cursor, Error, ErrorKind},
    net::ToSocketAddrs,
};

pub const SOCKS5_VERSION: u8 = 5;

#[cfg_attr(rustfmt, rustfmt_skip)]
#[allow(dead_code)]
pub mod s5code {
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

#[derive(Clone, Debug, Copy)]
#[allow(dead_code)]
enum Method {
    NoAuth,
    GssApi,
    NamePassword,
    NoAcceptMethod,
}

#[allow(dead_code)]
impl Method {
    fn as_u8(self) -> u8 {
        match self {
            Method::NoAuth => s5code::SOCKS5_METHOD_NO_AUTH,
            Method::GssApi => s5code::SOCKS5_METHOD_GSSAPI,
            Method::NamePassword => s5code::SOCKS5_METHOD_NAME_PASSWORD,
            Method::NoAcceptMethod => s5code::SOCKS5_METHOD_NO_ACCEPT,
        }
    }

    fn from_u8(code: u8) -> Option<Method> {
        match code {
            s5code::SOCKS5_METHOD_NO_AUTH => Some(Method::NoAuth),
            s5code::SOCKS5_METHOD_GSSAPI => Some(Method::GssApi),
            s5code::SOCKS5_METHOD_NAME_PASSWORD => Some(Method::NamePassword),
            s5code::SOCKS5_METHOD_NO_ACCEPT => Some(Method::NoAcceptMethod),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct HandShakeResponse {
    pub msg: [u8; 2],
}

impl HandShakeResponse {
    fn new(code: u8) -> Self {
        let msg: [u8; 2] = [SOCKS5_VERSION, code];
        HandShakeResponse { msg }
    }

    fn set_code(&mut self, code: u8) {
        self.msg[1] = code;
    }

    async fn write_to<'a, W>(&'a self, w: &'a mut W) -> io::Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        w.write_all(&self.msg[..]).await
    }
}

pub struct Socks5HandShake;

impl Socks5HandShake {
    pub async fn deal_with<'a, R, W>(r: &'a mut R, w: &'a mut W) -> Option<Error>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let mut leaky = [0u8; 16];
        let mut resp = HandShakeResponse::new(s5code::SOCKS5_METHOD_NO_ACCEPT);
        let err = match unsafe { r.read(&mut leaky[..]).await } {
            Ok(read_len) => {
                if read_len < 2 {
                    return Some(Error::new(
                        ErrorKind::Other,
                        "encounter un-expected eof or not receive enough data",
                    ));
                }

                let mut reader = Cursor::new(&leaky[..2]);
                if reader.get_u8() != SOCKS5_VERSION {
                    return Some(Error::new(ErrorKind::Other, "wrong version number"));
                }

                let method_num = reader.get_u8();
                if read_len != usize::from(2 + method_num) {
                    return Some(Error::new(ErrorKind::Other, "not receive all autu methods data"));
                }

                if let Some(_) = &leaky[2..read_len]
                    .iter()
                    .position(|u| *u == s5code::SOCKS5_METHOD_NO_AUTH)
                {
                    resp.set_code(s5code::SOCKS5_METHOD_NO_AUTH);

                    None
                } else {
                    Some(Error::new(ErrorKind::Other, "no acceptable method"))
                }
            }

            Err(e) => Some(e),
        };

        match resp.write_to(w).await {
            Ok(_) => err,
            Err(e) => err.or(Some(e)),
        }
    }
}

#[derive(PartialEq, Clone, Debug, Copy)]
enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

#[allow(dead_code)]
impl Command {
    fn as_u8(&self) -> u8 {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        match self {
            Command::Connect        => s5code::SOCKS5_COMMAND_CONNECT,
            Command::Bind           => s5code::SOCKS5_COMMAND_BIND,
            Command::UdpAssociate   => s5code::SOCKS5_COMMAND_UDP_ASSOCIATE,
        }
    }

    fn from_u8(code: u8) -> Option<Command> {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        match code {
            s5code::SOCKS5_COMMAND_CONNECT          => Some(Command::Connect),
            s5code::SOCKS5_COMMAND_BIND             => Some(Command::Bind),
            s5code::SOCKS5_COMMAND_UDP_ASSOCIATE    => Some(Command::UdpAssociate),
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

#[allow(dead_code)]
impl AddrType {
    fn as_u8(&self) -> u8 {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        match self {
            AddrType::V4        => s5code::SOCKS5_ADDRTYPE_V4,
            AddrType::Domain    => s5code::SOCKS5_ADDRTYPE_DOMAIN,
            AddrType::V6        => s5code::SOCKS5_ADDRTYPE_V6,
        }
    }

    fn from_u8(code: u8) -> AddrType {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        match code {
            s5code::SOCKS5_ADDRTYPE_V4      => AddrType::V4,
            s5code::SOCKS5_ADDRTYPE_DOMAIN  => AddrType::Domain,
            s5code::SOCKS5_ADDRTYPE_V6      => AddrType::V6,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, Copy)]
#[allow(dead_code)]
pub enum Reply {
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

#[allow(dead_code)]
impl Reply {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn as_u8(&self) -> u8 {
        match self {
            Reply::Succeeded                => s5code::SOCKS5_REPLY_SUCCEEDED,
            Reply::GeneralFailure           => s5code::SOCKS5_REPLY_GENERAL_FAILURE,
            Reply::ConnectDisallowed        => s5code::SOCKS5_REPLY_CONNECT_DISALLOWED,
            Reply::NetworkUnreachable       => s5code::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Reply::HostUnreachable          => s5code::SOCKS5_REPLY_HOST_UNREACHABLE,
            Reply::ConnectRefused           => s5code::SOCKS5_REPLY_CONNECT_REFUSED,
            Reply::TtlExpired               => s5code::SOCKS5_REPLY_TTL_EXPIRED,
            Reply::CommandNotSupported      => s5code::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Reply::AddrtypeNotSupported     => s5code::SOCKS5_REPLY_ADDRTYPE_NOT_SUPPORTED,
        }
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn from_u8(code: u8) -> Option<Reply> {
        match code {
            s5code::SOCKS5_REPLY_SUCCEEDED              => Some(Reply::Succeeded),
            s5code::SOCKS5_REPLY_GENERAL_FAILURE        => Some(Reply::GeneralFailure),
            s5code::SOCKS5_REPLY_CONNECT_DISALLOWED     => Some(Reply::ConnectDisallowed),
            s5code::SOCKS5_REPLY_NETWORK_UNREACHABLE    => Some(Reply::NetworkUnreachable),
            s5code::SOCKS5_REPLY_HOST_UNREACHABLE       => Some(Reply::HostUnreachable),
            s5code::SOCKS5_REPLY_CONNECT_REFUSED        => Some(Reply::ConnectRefused),
            s5code::SOCKS5_REPLY_TTL_EXPIRED            => Some(Reply::TtlExpired),
            s5code::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED  => Some(Reply::CommandNotSupported),
            s5code::SOCKS5_REPLY_ADDRTYPE_NOT_SUPPORTED => Some(Reply::AddrtypeNotSupported),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub enum Address {
    SocketAddr(net::SocketAddr),
    DomainName(String, u16),
}

impl Address {
    #[allow(dead_code)]
    pub async fn connect<'a, W>(&'a self, w: &'a mut W) -> io::Result<TcpStream>
    where
        W: AsyncWriteExt + Unpin,
    {
        let succ = [
            SOCKS5_VERSION,
            Reply::Succeeded.as_u8(),
            0,
            s5code::SOCKS5_ADDRTYPE_V4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];

        let mut fail = [
            SOCKS5_VERSION,
            Reply::GeneralFailure.as_u8(),
            0,
            s5code::SOCKS5_ADDRTYPE_V4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];

        let rlt = match self {
            Address::SocketAddr(addr) => TcpStream::connect(*addr).await,

            Address::DomainName(ref dmname, port) => {
                let mut v: Vec<net::SocketAddr> = Vec::new();
                if let Ok(addrs) = format!("{}:{}", dmname, port).to_socket_addrs() {
                    v = addrs.collect();
                }

                let mut conn_rlt = Err(ErrorKind::AddrNotAvailable.into());
                for addr in v {
                    match TcpStream::connect(addr).await {
                        Ok(s) => {
                            conn_rlt = Ok(s);
                            break;
                        }

                        Err(e) => conn_rlt = Err(e),
                    }
                }

                conn_rlt
            }
        };

        match rlt {
            Err(ref e) => {
                #[cfg_attr(rustfmt, rustfmt_skip)]
                let code = match e.kind() {
                    ErrorKind::ConnectionRefused    => Reply::ConnectRefused,
                    ErrorKind::ConnectionAborted    => Reply::ConnectDisallowed,
                    _                               => Reply::NetworkUnreachable,
                };
                fail[1] = code.as_u8();

                let _ = w.write_all(&fail).await;
            }

            Ok(_) => {
                let _ = w.write_all(&succ).await;
            }
        }

        rlt
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Address::SocketAddr(ref addr) => write!(f, "{}", addr),
            Address::DomainName(ref dmname, ref port) => write!(f, "{}:{}", dmname, port),
        }
    }
}

pub struct ReadAddress;

impl ReadAddress {
    pub fn read_from(buf: &[u8]) -> io::Result<Address> {
        let mut stream = Cursor::new(buf);
        let atyp = AddrType::from_u8(stream.get_u8());
        let address = match atyp {
            AddrType::V4 => {
                debug_assert_eq!(buf.len(), 1 + 4 + 2);

                let addr_v4 = IpAddr::V4(Ipv4Addr::new(
                    stream.get_u8(),
                    stream.get_u8(),
                    stream.get_u8(),
                    stream.get_u8(),
                ));
                let port = stream.get_u16_be();

                Address::SocketAddr(net::SocketAddr::new(addr_v4, port))
            }

            AddrType::V6 => {
                debug_assert_eq!(buf.len(), 1 + 16 + 2);

                let addr_v6 = IpAddr::V6(Ipv6Addr::new(
                    stream.get_u16_be(),
                    stream.get_u16_be(),
                    stream.get_u16_be(),
                    stream.get_u16_be(),
                    stream.get_u16_be(),
                    stream.get_u16_be(),
                    stream.get_u16_be(),
                    stream.get_u16_be(),
                ));
                let port = stream.get_u16_be();

                Address::SocketAddr(net::SocketAddr::new(addr_v6, port))
            }
            AddrType::Domain => {
                debug_assert!(buf.len() > 2);
                let dmlen = stream.get_u8() as usize;
                debug_assert_eq!(buf.len(), 2 + dmlen + 2);

                let dmname = String::from_utf8_lossy(&buf[2..2 + dmlen]).into();
                stream.set_position((2 + dmlen) as u64);
                let port = stream.get_u16_be();
                Address::DomainName(dmname, port)
            }
        };

        Ok(address)
    }
}

pub struct TcpConnect;

impl TcpConnect {
    pub async fn deal_with<'a, R, W>(r: &'a mut R, w: &'a mut W, leaky: &'a mut [u8]) -> io::Result<usize>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let mut resp = [
            SOCKS5_VERSION,
            s5code::SOCKS5_REPLY_SUCCEEDED,
            0,
            s5code::SOCKS5_ADDRTYPE_V4,
        ];

        let rlt = match unsafe { r.read(&mut leaky[..]).await } {
            Err(e) => {
                resp[1] = s5code::SOCKS5_REPLY_GENERAL_FAILURE;
                let _ = w.write_all(&resp).await;

                Err(e)
            }

            Ok(n) if n > 4 => {
                let mut stream = Cursor::new(&leaky[..n]);
                let (ver, cmd, _) = (stream.get_u8(), stream.get_u8(), stream.get_u8());
                if ver != SOCKS5_VERSION {
                    resp[1] = s5code::SOCKS5_REPLY_GENERAL_FAILURE;
                    let _ = w.write_all(&resp).await;

                    return Err(Error::new(ErrorKind::Other, "tcp connect invalid socks5 version"));
                }

                if Command::from_u8(cmd).unwrap() != Command::Connect {
                    resp[1] = s5code::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED;
                    let _ = w.write_all(&resp).await;

                    return Err(Error::new(ErrorKind::Other, "tcp connect command not supported"));
                }

                Ok(n)
            }

            Ok(n) if n == 0 => {
                resp[1] = s5code::SOCKS5_REPLY_CONNECT_REFUSED;
                let _ = w.write_all(&resp).await;

                Err(Error::new(ErrorKind::UnexpectedEof, "connection closed"))
            }

            Ok(_) => {
                resp[1] = s5code::SOCKS5_REPLY_CONNECT_DISALLOWED;
                let _ = w.write_all(&resp).await;

                Err(Error::new(ErrorKind::Other, "tcp connect not enough data"))
            }
        };

        rlt
    }
}
