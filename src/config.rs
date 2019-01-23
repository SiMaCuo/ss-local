use super::crypto::cipher::CipherMethod;
use bytes::Bytes;
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ConfigJson {
    local_port: u16,
    server_ip: String,
    server_port: u16,
    password: String,
    method: String,
    timeout: u64,
}

impl ConfigJson {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let f = File::open(path)?;

        let c: ConfigJson = serde_json::from_reader(f)?;

        Ok(c)
    }
}

pub struct SsConfig {
    pub local_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub enc_key: Bytes,
    pub method: Bytes,
    pub keeplive: Option<Duration>,
}

impl SsConfig {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let json = ConfigJson::new(path)?;
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), json.local_port);
        let server_addr = format!("{}:{}", json.server_ip, json.server_port).parse().unwrap();
        let keeplive = if json.timeout == 0 {
            None
        } else {
            Some(Duration::from_secs(json.timeout))
        };

        let s = SsConfig {
            local_addr,
            server_addr,
            enc_key: CipherMethod::derive_key(json.password.as_bytes()),
            method: Bytes::from(json.method),
            keeplive,
        };

        Ok(s)
    }
}
