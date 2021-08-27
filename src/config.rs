use crate::crypto::cipher::CipherMethod;
#[cfg(target_os = "windows")]
use crate::fc::acl::{Acl, AclResult};
use bytes::Bytes;
use serde_derive::Deserialize;
use std::{
    fs::File,
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Deserialize, Clone, Debug)]
struct ConfigJson {
    local_port: u16,
    server_ip: String,
    server_port: u16,
    password: String,
    method: String,
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
    server_addr: SocketAddr,
    enc_key: Bytes,
    method: CipherMethod,
    #[cfg(target_os = "windows")]
    acl: Acl,
}

impl SsConfig {
    pub fn new(dir: PathBuf, path: &Path) -> Result<Self, Error> {
        let json = ConfigJson::new(path)?;
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), json.local_port);
        let server_addr = format!("{}:{}", json.server_ip, json.server_port).parse().unwrap();

        let mut acl_path = dir.clone();
        acl_path.push(json.acl);
        if acl_path.is_file() == false {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!(
                    "this program use acl file for remote proxy, but {} not exist or not file",
                    acl_path.display()
                ),
            ));
        }

        #[cfg(target_os = "windows")]
        let mut s = SsConfig {
            local_addr,
            server_addr,
            enc_key: CipherMethod::derive_key(json.password.as_bytes(), 32),
            method: json.method.parse().unwrap(),
            acl: Acl::new(),
        };
        #[cfg(target_os = "windows")]
        s.acl.init(acl_path)?;

        #[cfg(target_os = "linux")]
        let s = SsConfig {
            local_addr,
            server_addr,
            enc_key: CipherMethod::derive_key(json.password.as_bytes(), 32),
            method: json.method.parse().unwrap(),
        };

        Ok(s)
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.local_addr
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

    #[cfg(target_os = "windows")]
    pub fn acl_match(&self, m: &str) -> AclResult {
        self.acl.acl_match(m)
    }
}
