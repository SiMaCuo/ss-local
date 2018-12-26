use super::socks5::*;
use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum CliError {
    StdIo(io::Error),
    ExceedWriteSize,
    Sock5(u8),
}

use self::CliError::*;

impl CliError {
    pub fn wouldblock(&self) -> bool {
        match self {
            StdIo(ref e) => {
                return e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted;
            }

            _ => false,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StdIo(ref e) => write!(f, "{}", e),
            ExceedWriteSize => f.write_str(
                "Exceeded the maximum write limit, please wait for the next write event to trigger",
            ),
            Sock5(ref e) => match *e {
                Rep::GENERAL_FAILURE => f.write_str("general SOCKS server failure"),
                Rep::CONNECT_DISALLOWED => f.write_str("connection not allowed by ruleset"),
                Rep::NETWORK_UNREACHABLE => f.write_str("network unreachable"),
                Rep::HOST_UNREACHABLE => f.write_str("host unreachable"),
                Rep::CONNECT_REFUSED => f.write_str("connection refused"),
                Rep::TTL_EXPIRED => f.write_str("ttl expired"),
                Rep::CMD_NOT_SUPPORTED => f.write_str("command not supported"),
                Rep::ADDRTYPE_NOT_SUPPORTED => f.write_str("address type not supported"),
                Method::NO_ACCEPT_METHOD => f.write_str("no acceptable methods"),
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
