use super::conn;
use super::socks5::*;
use std::{error::Error, fmt, io};

#[derive(Debug, PartialEq)]
pub enum CloseStream {
    Keep,
    LocalRead,
    LocalWrite,
    LocalBoth,
    RemoteRead,
    RemoteWrite,
    RemoteBoth,
    Both,
}
use self::CloseStream::*;

impl fmt::Display for CloseStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Keep => write!(f, "Keep"),
            LocalRead => write!(f, "Local Read"),
            LocalWrite => write!(f, "Local Write"),
            LocalBoth => write!(f, "Local Both"),
            RmoteRead => write!(f, "Remote Read"),
            RemoteWrite => write!(f, "Remote Write"),
            RemoteBoth => write!(f, "Remote Both"),
        }
    }
}

impl Error for CloseStream {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self)
    }
}

pub struct Close(CloseStream, CloseStream);

impl fmt::Display for Close {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "local end {}, remote end {}", self.0, self.1)
    }
}
#[derive(Debug)]
pub enum CliError {
    StdIo(io::Error),
    Sock5(u8),
}

use self::CliError::*;

impl CliError {
    pub fn is_wouldblock(&self) -> bool {
        match *self {
            StdIo(ref e) => conn::is_wouldblock(e),
            _ => false,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StdIo(ref e) => write!(f, "{}", e),
            Sock5(ref e) => match *e {
                Rep::GENERAL_FAILURE => write!(f, "general SOCKS server failure"),
                Rep::CONNECT_DISALLOWED => write!(f, "connection not allowed by ruleset"),
                Rep::NETWORK_UNREACHABLE => write!(f, "network unreachable"),
                Rep::HOST_UNREACHABLE => write!(f, "host unreachable"),
                Rep::CONNECT_REFUSED => write!(f, "connection refused"),
                Rep::TTL_EXPIRED => write!(f, "ttl expired"),
                Rep::CMD_NOT_SUPPORTED => write!(f, "command not supported"),
                Rep::ADDRTYPE_NOT_SUPPORTED => write!(f, "address type not supported"),
                Method::NO_ACCEPT_METHOD => write!(f, "no acceptable methods"),
                _ => unreachable!(),
            },
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self)
    }
}

impl From<io::Error> for CliError {
    fn from(err: io::Error) -> CliError {
        StdIo(err)
    }
}

impl From<io::ErrorKind> for CliError {
    fn from(kind: io::ErrorKind) -> CliError {
        StdIo(io::Error::from(kind))
    }
}

impl From<u8> for CliError {
    fn from(err: u8) -> CliError {
        match err {
            Rep::GENERAL_FAILURE
            | Rep::CONNECT_DISALLOWED
            | Rep::NETWORK_UNREACHABLE
            | Rep::HOST_UNREACHABLE
            | Rep::CONNECT_REFUSED
            | Rep::TTL_EXPIRED
            | Rep::CMD_NOT_SUPPORTED
            | Rep::ADDRTYPE_NOT_SUPPORTED
            | Method::NO_ACCEPT_METHOD => Sock5(err),
            _ => panic!("u8 type sock error code can't recognize"),
        }
    }
}
