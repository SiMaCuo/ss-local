pub const SOCKS5_VERSION: u8 = 5;

pub enum Method {
    NoAuthRequired = 0x00,
    UnAcceptable = 0xff,
}

pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

pub enum AddrType {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectDisallowed = 0x02,
    NetwrokkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectRefused = 0x05,
    TTLExpired = 0x06,
    CmdNotSupported = 0x07,
    AddrTypeNotSupported = 0x08,
    Unassigned = 0x09,
}

#[repr(C, packed)]
pub struct MethodSelectRequest {
    Ver: u8,
    NMethods: u8, 
    Methods: u8,
}

impl MethodSelectRequest {
    pub fn new() {
        SOCKS5_VERSION,
        1,
        Method::NoAuthRequired as u8,
    }
}

#[repr(C, packed)]
pub struct MethodSelectResponse {
    Ver: u8,
    Methods: u8,
}

impl MethodSelectResponse {
    pub fn new() {
        MethodSelectResponse {
            SOCKS5_VERSION,
            Method::NoAuthRequired as u8,
        }
    }
}

#[repr(C, packed)]
pub struct Request {
    Ver: u8,
    Cmd: u8,
    Rsv: u8,
    ATyp: u8,
}

impl Request {
    pub fn new() -> Self {
        Request {
            SOCKS5_VERSION,
            0xff,
            0xff,
            0xff,
        }
    }
}

#[repr(C, packed)]
pub struct Response {
    Ver: u8,
    Rep: u8,
    Rsv: u8,
    ATyp: u8,
}

impl Response {
    pub fn new() -> Self {
        Response {
            SOCKS5_VERSION,
            0xff,
            0xff,
            0xff,
        }
    }
}
