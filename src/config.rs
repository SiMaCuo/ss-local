use serde_derive::{Serialize, Deserialize};
use std::{fs::File, path::Path, error};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub local_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub password: String,
    pub method: String,
}

impl Config {
    pub fn new(path: &Path) -> Result<Config, Box<error::Error>> {
        let f = File::open(path)?;
        
        let c: Config = serde_json::from_reader(f)?;

        Ok(c)
    }
}


