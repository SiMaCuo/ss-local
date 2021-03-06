use bytes::Bytes;
use fnv::FnvHashSet;
use ipnet::IpNet;
use log::info;
use parking_lot::RwLock;
use pcre2::bytes::Regex;
use rand::{rngs::SmallRng, FromEntropy, Rng};
use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
    path::Path,
};

const DEFAULT_RULE_LRU_SIZE: usize = 256;
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

struct BypassHost {
    h: FnvHashSet<Bytes>,
    v: Vec<Bytes>,
    cap: usize,
    rng: SmallRng,
}

impl BypassHost {
    pub fn with_capacity(capacity: usize) -> Self {
        BypassHost {
            h: FnvHashSet::default(),
            v: Vec::with_capacity(capacity),
            cap: capacity,
            rng: SmallRng::from_entropy(),
        }
    }

    pub fn is_match(&self, host: &str) -> bool {
        return self.h.contains(host.as_bytes());
    }

    pub fn add_rule(&mut self, host: &str) {
        let bh = Bytes::from(host);
        if self.v.len() < self.cap {
            let bv = bh.slice_from(0);
            self.h.insert(bh);
            self.v.push(bv);
        } else {
            let index = self.rng.gen_range(0, self.cap);
            unsafe {
                let ptr = self.v.as_mut_ptr().add(index);
                let b = std::ptr::replace(ptr, bh);
                self.h.remove(&b);
            }
        }
    }
}

struct RuleLru {
    cache: Vec<Regex>,
    cap: usize,
    rng: SmallRng,
}

impl RuleLru {
    pub fn with_capacity(capacity: usize) -> Self {
        RuleLru {
            cache: Vec::with_capacity(capacity),
            cap: capacity,
            rng: SmallRng::from_entropy(),
        }
    }

    pub fn is_match(&self, m: &str) -> bool {
        for rule in self.cache.iter() {
            if let Ok(true) = rule.is_match(m.as_bytes()) {
                return true;
            }
        }

        return false;
    }

    pub fn add_rule(&mut self, rule: Regex) {
        if self.cache.len() < self.cap {
            self.cache.push(rule);
        } else {
            let index = self.rng.gen_range(0, self.cap);
            unsafe {
                let ptr = self.cache.as_mut_ptr().add(index);
                std::ptr::replace(ptr, rule);
            }
        }
    }
}

struct Rules {
    ips: Vec<IpAddr>,
    net: Vec<IpNet>,
    lru: RwLock<RuleLru>,
    re: Vec<Regex>,
}

impl Rules {
    fn new() -> Self {
        Rules {
            ips: Vec::new(),
            net: Vec::new(),
            lru: RwLock::new(RuleLru::with_capacity(DEFAULT_RULE_LRU_SIZE)),
            re: Vec::with_capacity(2048),
        }
    }

    fn add_rule(&mut self, rule: &str) {
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
            {
                if self.lru.read().is_match(m) {
                    return true;
                }
            }

            for rule in self.re.iter() {
                match rule.is_match(m.as_bytes()) {
                    Ok(true) => {
                        self.lru.write().add_rule(rule.clone());
                        return true;
                    }

                    _ => {}
                }
            }
        }

        return false;
    }
}

#[derive(PartialEq)]
pub enum AclResult {
    ByPass,
    RemoteProxy,
    Reject,
}

pub struct Acl {
    bypass_hosts: RwLock<BypassHost>,
    black_list_rules: Rules,
    white_list_rules: Rules,
    outbound_block_list_rules: Rules,
}

impl Acl {
    pub fn new() -> Self {
        Acl {
            bypass_hosts: RwLock::new(BypassHost::with_capacity(DEFAULT_RULE_LRU_SIZE * 2)),
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
            } else if l.starts_with("[proxy_list]") || l.starts_with("[black_list]") {
                rules = Some(&mut self.black_list_rules);
                continue;
            } else if l.starts_with("[bypass_all]") || l.starts_with("[white_list]") {
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
        let result = if self.bypass_hosts.read().is_match(&m) {
            return AclResult::ByPass;
        } else if self.white_list_rules.is_match(&m) {
            AclResult::ByPass
        } else if self.outbound_block_list_rules.is_match(&m) {
            AclResult::Reject
        } else if self.black_list_rules.is_match(&m) {
            AclResult::RemoteProxy
        } else {
            AclResult::ByPass
        };

        if result == AclResult::ByPass {
            self.bypass_hosts.write().add_rule(m);
        }

        result
    }
}
