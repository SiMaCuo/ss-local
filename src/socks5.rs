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




