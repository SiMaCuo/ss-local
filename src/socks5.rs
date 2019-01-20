use futures::prelude::*;
use std::{
    fmt::{self, Debug, Formatter},
    io::{self, Cursor},
    net::{self, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub const CMD_HEAD_LEN: usize = 4;
pub const CMD_IPV4_LEN: usize = CMD_HEAD_LEN + 4 + 2;
pub const CMD_IPV6_LEN: usize = CMD_HEAD_LEN + 16 + 2;
pub const METHOD_SELECT_HEAD_LEN: usize = 2;

pub const SOCKS5_VERSION: u8 = 5;
const SOCKS5_METHOD_NO_AUTH: u8 = 0x0;
const SOCKS5_METHOD_GSSAPI: u8 = 0x1;
const SOCKS5_METHOD_NAME_PASSWORD: u8 = 0x3;
const SOCKS5_METHOD_NO_ACCEPT: u8 = 0xff;
const SOCKS5_COMMAND_CONNECT: u8 = 0x1;
const SOCKS5_COMMAND_BIND: u8 = 0x2;
const SOCKS5_COMMAND_UDP_ASSOCIATE: u8 = 0x3;
const SOCKS5_ADDRTYPE_V4: u8 = 0x01;
const SOCKS5_ADDRTYPE_DOMAIN: u8 = 0x03;
const SOCKS5_ADDRTYPE_V6: u8 = 0x04;
const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REPLY_CONNECT_DISALLOWED: u8 = 0x02;
const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REPLY_CONNECT_REFUSED: u8 = 0x05;
const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;
const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REPLY_ADDRTYPE_NOT_SUPPORTED: u8 = 0x08;

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
            Method::NoAuth => SOCKS5_METHOD_NO_AUTH,
            Method::GssApi => SOCKS5_METHOD_GSSAPI,
            Method::NamePassword => SOCKS5_METHOD_NAME_PASSWORD,
            Method::NoAcceptMethod => SOCKS5_METHOD_NO_ACCEPT,
        }
    }

    fn from_u8(code: u8) -> Option<Method> {
        match code {
            SOCKS5_METHOD_NO_AUTH => Some(Method::NoAuth),
            SOCKS5_METHOD_GSSAPI => Some(Method::GssApi),
            SOCKS5_METHOD_NAME_PASSWORD => Some(Method::NamePassword),
            SOCKS5_METHOD_NO_ACCEPT => Some(Method::NoAcceptMethod),
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
            Command::Connect => SOCKS5_COMMAND_CONNECT,
            Command::Bind => SOCKS5_COMMAND_BIND,
            Command::UdpAssociate => SOCKS5_COMMAND_UDP_ASSOCIATE,
        }
    }

    fn from_u8(code: u8) -> Option<Command> {
        match code {
            SOCKS5_COMMAND_CONNECT => Some(Command::Connect),
            SOCKS5_COMMAND_BIND => Some(Command::Bind),
            SOCKS5_COMMAND_UDP_ASSOCIATE => Some(Command::UdpAssociate),
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
            AddrType::V4 => SOCKS5_ADDRTYPE_V4,
            AddrType::Domain => SOCKS5_ADDRTYPE_DOMAIN,
            AddrType::V6 => SOCKS5_ADDRTYPE_V6,
        }
    }

    fn from_u8(code: u8) -> Option<AddrType> {
        match code {
            SOCKS5_ADDRTYPE_V4 => Some(AddrType::V4),
            SOCKS5_ADDRTYPE_DOMAIN => Some(AddrType::Domain),
            SOCKS5_ADDRTYPE_V6 => Some(AddrType::V6),
            _ => None,
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
            Reply::Succeeded => SOCKS5_REPLY_SUCCEEDED,
            Reply::GeneralFailure => SOCKS5_REPLY_GENERAL_FAILURE,
            Reply::ConnectDisallowed => SOCKS5_REPLY_CONNECT_DISALLOWED,
            Reply::NetworkUnreachable => SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Reply::HostUnreachable => SOCKS5_REPLY_HOST_UNREACHABLE,
            Reply::ConnectRefused => SOCKS5_REPLY_CONNECT_REFUSED,
            Reply::TtlExpired => SOCKS5_REPLY_TTL_EXPIRED,
            Reply::CommandNotSupported => SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Reply::AddrtypeNotSupported => SOCKS5_REPLY_ADDRTYPE_NOT_SUPPORTED,
        }
    }

    fn from_u8(code: u8) -> Option<Reply> {
        match code {
            SOCKS5_REPLY_SUCCEEDED => Some(Reply::Succeeded),
            SOCKS5_REPLY_GENERAL_FAILURE => Some(Reply::GeneralFailure),
            SOCKS5_REPLY_CONNECT_DISALLOWED => Some(Reply::ConnectDisallowed),
            SOCKS5_REPLY_NETWORK_UNREACHABLE => Some(Reply::NetworkUnreachable),
            SOCKS5_REPLY_HOST_UNREACHABLE => Some(Reply::HostUnreachable),
            SOCKS5_REPLY_CONNECT_REFUSED => Some(Reply::ConnectRefused),
            SOCKS5_REPLY_TTL_EXPIRED => Some(Reply::TtlExpired),
            SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => Some(Reply::CommandNotSupported),
            SOCKS5_REPLY_ADDRTYPE_NOT_SUPPORTED => Some(Reply::AddrtypeNotSupported),
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

#[derive(Clone, Debug)]
pub enum Address {
    SocketAddr(net::SocketAddr),
    DomainName(String, u16),
}
