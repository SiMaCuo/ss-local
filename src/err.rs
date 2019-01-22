// use super::socks5::*;
// use std::{error::Error, fmt, io};
//
// #[derive(Debug)]
// pub enum NetError {
//     StdIo(io::Error),
//     ExceedReadSize,
//     Sock5(u8),
// }
//
// use self::NetError::*;
//
// impl NetError {
//     pub fn wouldblock(&self) -> bool {
//         match self {
//             StdIo(ref e) => {
//                 return e.kind() == io::ErrorKind::WouldBlock
//                     || e.kind() == io::ErrorKind::Interrupted;
//             }
//
//             _ => false,
//         }
//     }
// }
//
// impl fmt::Display for NetError {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             StdIo(ref e) => write!(f, "{}", e),
//             ExceedReadSize => f.write_str(
//                 "exceeded the maximum read buffer limit, there is unread data in the socket buffer",
//             ),
//             Sock5(ref e) => match *e {
//                 Rep::GENERAL_FAILURE => f.write_str("general SOCKS server failure"),
//                 Rep::CONNECT_DISALLOWED => f.write_str("connection not allowed by ruleset"),
//                 Rep::NETWORK_UNREACHABLE => f.write_str("network unreachable"),
//                 Rep::HOST_UNREACHABLE => f.write_str("host unreachable"),
//                 Rep::CONNECT_REFUSED => f.write_str("connection refused"),
//                 Rep::TTL_EXPIRED => f.write_str("ttl expired"),
//                 Rep::CMD_NOT_SUPPORTED => f.write_str("command not supported"),
//                 Rep::ADDRTYPE_NOT_SUPPORTED => f.write_str("address type not supported"),
//                 Method::NO_ACCEPT_METHOD => f.write_str("no acceptable methods"),
//                 _ => unreachable!(),
//             },
//         }
//     }
// }
//
// impl Error for NetError {
//     fn source(&self) -> Option<&(dyn Error + 'static)> {
//         Some(self)
//     }
// }
//
// impl From<io::Error> for NetError {
//     fn from(err: io::Error) -> NetError {
//         StdIo(err)
//     }
// }
//
// impl From<io::ErrorKind> for NetError {
//     fn from(kind: io::ErrorKind) -> NetError {
//         StdIo(io::Error::from(kind))
//     }
// }
//
// impl From<u8> for NetError {
//     fn from(err: u8) -> NetError {
//         match err {
//             Rep::GENERAL_FAILURE
//             | Rep::CONNECT_DISALLOWED
//             | Rep::NETWORK_UNREACHABLE
//             | Rep::HOST_UNREACHABLE
//             | Rep::CONNECT_REFUSED
//             | Rep::TTL_EXPIRED
//             | Rep::CMD_NOT_SUPPORTED
//             | Rep::ADDRTYPE_NOT_SUPPORTED
//             | Method::NO_ACCEPT_METHOD => Sock5(err),
//             _ => panic!("u8 type sock error code can't recognize"),
//         }
//     }
// }
