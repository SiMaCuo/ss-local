pub const SOCKS5_VERSION: u8 = 5;

pub enum Socks5Phase {
    Initialize,
    Handshake,
    Http,
    Streaming,
}

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
    ver: u8,
    nmethods: u8, 
    method: u8,
}

impl MethodSelectRequest {
    pub fn new()-> Self {
        MethodSelectRequest {
            ver: SOCKS5_VERSION,
            nmethods: 1,
            method: Method::UnAcceptable as u8
        }
    }
}

#[repr(C, packed)]
pub struct MethodSelectResponse {
    ver: u8,
    method: u8,
}

impl MethodSelectResponse {
    pub fn new() -> Self {
        MethodSelectResponse {
            ver: SOCKS5_VERSION,
            method: Method::UnAcceptable as u8,
        }
    }
}

#[repr(C, packed)]
pub struct Request {
    ver: u8,
    cmd: u8,
    rsv: u8,
    atyp: u8,
}

impl Request {
    pub fn new() -> Self {
        Request {
            ver: SOCKS5_VERSION,
            cmd: 0xff,
            rsv: 0,
            atyp: 0xff,
        }
    }
}

#[repr(C, packed)]
pub struct Response {
    ver: u8,
    rep: u8,
    rsv: u8,
    atyp: u8,
}

impl Response {
    pub fn new() -> Self {
        Response {
            ver: SOCKS5_VERSION,
            rep: Reply::Succeeded as u8,
            rsv: 0,
            atyp: AddrType::V4 as u8,
        }
    }
}
