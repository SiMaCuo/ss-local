// use ipset::IpSet;
use ipnet::IpNet;
use log::info;
use pcre2::bytes::Regex;
use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
    path::Path,
};

struct LineClear<'a> {
    line: &'a mut String,
}

impl<'a> LineClear<'a> {
    fn new(line: &'a mut String) -> Self {
        LineClear { line }
    }
}

impl<'a> Drop for LineClear<'a> {
    fn drop(&mut self) {
        self.line.clear();
    }
}

impl<'a> Deref for LineClear<'a> {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.line
    }
}

impl<'a> DerefMut for LineClear<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.line
    }
}

struct Rules {
    ips: Vec<IpAddr>,
    net: Vec<IpNet>,
    re: Vec<Regex>,
}

impl Rules {
    fn new() -> Self {
        Rules {
            ips: Vec::new(),
            net: Vec::new(),
            re: Vec::with_capacity(2048),
        }
    }

    pub fn add_rule(&mut self, rule: &str) {
        if let Ok(ip) = rule.parse::<IpAddr>() {
            self.ips.push(ip);
            return;
        }

        if let Ok(net) = rule.parse::<IpNet>() {
            self.net.push(net);
            return;
        }

        let _ = Regex::new(rule)
            .map_err(|err| {
                info!("rule {} failed {}", rule, err);
                err
            })
            .and_then(|re| {
                self.re.push(re);
                Ok(())
            });
    }

    pub fn is_match(&self, m: &str) -> bool {
        let addr = if let Ok(sockaddr) = m.parse::<SocketAddr>() {
            Some(sockaddr.ip())
        } else if let Ok(ipaddr) = m.parse::<IpAddr>() {
            Some(ipaddr)
        } else {
            None
        };

        if let Some(ipaddr) = addr {
            for net in self.net.iter() {
                if net.contains(&ipaddr) {
                    return true;
                }
            }

            for ip in self.ips.iter() {
                if &ipaddr == ip {
                    return true;
                }
            }
        } else {
            for rule in self.re.iter() {
                match rule.is_match(m.as_bytes()) {
                    Ok(true) => {
                        return true;
                    }

                    _ => {}
                }
            }
        }

        return false;
    }
}

pub enum AclResult {
    ByPass,
    RemoteProxy,
    Reject,
}

pub struct Acl {
    black_list_rules: Rules,
    white_list_rules: Rules,
    outbound_block_list_rules: Rules,
}

impl Acl {
    pub fn new() -> Self {
        Acl {
            black_list_rules: Rules::new(),
            white_list_rules: Rules::new(),
            outbound_block_list_rules: Rules::new(),
        }
    }

    pub fn init<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let fs = File::open(path)?;
        let mut buf = BufReader::new(fs);
        let mut rules: Option<&mut Rules> = None;

        let pat: &[_] = &[' ', '\t', '\r', '\n'];
        let mut line = String::with_capacity(512);
        while let Ok(n) = buf.read_line(&mut line) {
            if n == 0 {
                break;
            }

            let g = LineClear::new(&mut line);
            let l = g.trim_matches(pat);
            if l.len() == 0 || l.starts_with("#") {
                continue;
            }

            if l.starts_with("[outbound_block_list]") {
                rules = Some(&mut self.outbound_block_list_rules);
                continue;
            } else if l.starts_with("[black_list]") || l.starts_with("[bypass_list]") {
                rules = Some(&mut self.black_list_rules);
                continue;
            } else if l.starts_with("[white_list]") || l.starts_with("[proxy_list]") {
                rules = Some(&mut self.white_list_rules);
                continue;
            }

            if let Some(ref mut r) = rules {
                r.add_rule(l);
            }
        }

        Ok(())
    }

    pub fn acl_match(&self, m: &str) -> AclResult {
        if self.outbound_block_list_rules.is_match(m) {
            return AclResult::Reject;
        }

        if self.black_list_rules.is_match(m) {
            return AclResult::RemoteProxy;
        }

        return AclResult::ByPass;
    }
}
