use crate::{crypto::cipher::CipherMethod, fc::acl::Acl};
use bytes::Bytes;
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ConfigJson {
    local_port: u16,
    local_threadpool_size: usize,
    server_ip: String,
    server_port: u16,
    password: String,
    method: String,
    keepalive: u64,
    acl: String,
}

impl ConfigJson {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let f = File::open(path)?;

        let c: ConfigJson = serde_json::from_reader(f)?;

        Ok(c)
    }
}

pub struct SsConfig {
    local_addr: SocketAddr,
    local_threadpool_size: usize,
    server_addr: SocketAddr,
    enc_key: Bytes,
    method: CipherMethod,
    keeplive: Option<Duration>,
    acl: Acl,
}

impl SsConfig {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let json = ConfigJson::new(path)?;
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), json.local_port);
        let server_addr = format!("{}:{}", json.server_ip, json.server_port).parse().unwrap();
        let keeplive = if json.keepalive == 0 {
            None
        } else {
            Some(Duration::from_secs(json.keepalive))
        };

        let acl_path = Path::new(&json.acl);
        if acl_path.is_file() == false {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("{:?}, not exist or not file", acl_path),
            ));
        }

        let mut s = SsConfig {
            local_addr,
            local_threadpool_size: json.local_threadpool_size,
            server_addr,
            enc_key: CipherMethod::derive_key(json.password.as_bytes(), 32),
            method: json.method.parse().unwrap(),
            keeplive,
            acl: Acl::new(),
        };

        s.acl.init(acl_path)?;

        Ok(s)
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn romio_threadpool_size(&self) -> usize {
        self.local_threadpool_size
    }

    pub fn ss_server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    pub fn key_derived_from_pass(&self) -> Bytes {
        self.enc_key.clone()
    }

    pub fn method(&self) -> CipherMethod {
        self.method
    }

    pub fn keepalive(&self) -> Option<Duration> {
        self.keeplive
    }
}
