pub const SOCKS5_VERSION: u8 = 5;
pub const CMD_HEAD_LEN: usize = 4;
pub const CMD_IPV4_LEN: usize = CMD_HEAD_LEN + 4 + 2;
pub const CMD_IPV6_LEN: usize = CMD_HEAD_LEN + 16 + 2;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Stage {
    LocalConnected,
    SendMethodSelect,
    HandShake,
    RemoteConnecting,
    Streaming,
}

#[allow(dead_code, non_snake_case)]
pub mod Method {
    pub const NO_AUTH: u8 = 0x0;
    pub const GSSAPI: u8 = 0x1;
    pub const NAME_PASSWORD: u8 = 0x3;
    pub const NO_ACCEPT_METHOD: u8 = 0xff;
}

#[allow(dead_code, non_snake_case)]
pub mod Cmd {
    pub const CONNECT: u8 = 0x1;
    pub const BIND: u8 = 0x2;
    pub const UDP_ASSOCIATE: u8 = 0x3;
}

#[allow(dead_code, non_snake_case)]
pub mod AddrType {
    pub const V4: u8 = 0x1;
    pub const DOMAIN: u8 = 0x2;
    pub const V6: u8 = 0x3;
}

#[allow(dead_code, non_snake_case)]
pub mod Rep {
    pub const SUCCEEDED: u8 = 0x00;
    pub const GENERAL_FAILURE: u8 = 0x01;
    pub const CONNECT_DISALLOWED: u8 = 0x02;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECT_REFUSED: u8 = 0x05;
    pub const TTL_EXPIRED: u8 = 0x06;
    pub const CMD_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRTYPE_NOT_SUPPORTED: u8 = 0x08;
}

pub const METHOD_SELECT_HEAD_LEN: usize = 2;
