// use ipset::IpSet;
use regex::{self, Regex};
use std::{
    collections::LinkedList,
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};

struct Rules {
    rules: LinkedList<Regex>,
    lru: Option<Regex>,
}

impl Rules {
    fn new() -> Self {
        Rules {
            rules: LinkedList::new(),
            lru: None,
        }
    }

    pub fn add_rule(&mut self, rule: &str) -> Result<(), regex::Error> {
        Regex::new(rule).and_then(|re| {
            self.rules.push_back(re);

            Ok(())
        })
    }

    pub fn is_match(&self, m: &str) -> bool {
        if let Some(ref re) = self.lru {
            if re.is_match(m) {
                return true;
            }
        }

        for v in self.rules.iter() {
            if v.is_match(m) {
                self.lru = Some(v.clone());

                return true;
            }
        }

        return false;
    }
}

pub enum AclResult {
    ByPass,
    Block,
}

pub struct Acl {
    black_list_rules: Rules,
    white_list_rules: Rules,
    outbound_block_list_rules: Rules,
}

impl Acl {
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let fs = File::open(path)?;
        let mut buf = BufReader::new(fs);
        let mut line = String::with_capacity(512);
        let mut rules: Option<&mut Rules> = None;

        let mut acl = Acl {
            black_list_rules: Rules::new(),
            white_list_rules: Rules::new(),
            outbound_block_list_rules: Rules::new(),
        };

        let pat: &[_] = &[' ', '\t', '\r', '\n', '#'];
        while let Ok(n) = buf.read_line(&mut line) {
            if n == 0 {
                continue;
            }

            let l = line.trim_matches(pat);
            if l.len() == 0 {
                continue;
            }

            if l.starts_with("[outbound_block_list]") {
                // list_ipv4 = &outbound_block_list_ipv4;
                // list_ipv6 = &outbound_block_list_ipv6;
                rules = Some(&mut acl.outbound_block_list_rules);
                continue;
            } else if l.starts_with("[black_list]") || l.starts_with("[bypass_list]") {
                // list_ipv4 = &black_list_ipv4;
                // list_ipv6 = &black_list_ipv6;
                rules = Some(&mut acl.black_list_rules);
                continue;
            } else if l.starts_with("[white_list]") || l.starts_with("[proxy_list]") {
                // list_ipv4 = &white_list_ipv4;
                // list_ipv6 = &white_list_ipv6;
                rules = Some(&mut acl.white_list_rules);
                continue;
            } else if l.starts_with("[reject_all]") || l.starts_with("[bypass_all]") {
                // acl_mode = WHITE_LIST;
                continue;
            } else if l.starts_with("[accept_all]") || l.starts_with("[proxy_all]") {
                // acl_mode = BLACK_LIST;
                continue;
            }

            if let Some(ref mut r) = rules {
                r.add_rule(l);
            }
        }

        Ok(acl)
    }

    pub fn acl_match_host(&self, host: &str) -> AclResult {
        if self.black_list_rules.is_match(host) {
            return AclResult::Block;
        }

        AclResult::ByPass
    }

    pub fn outbound_block_match_host(&self, host: &str) -> AclResult {
        if self.outbound_block_list_rules.is_match(host) {
            return AclResult::Block;
        }

        AclResult::ByPass
    }
}
