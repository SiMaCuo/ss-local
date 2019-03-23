// use ipset::IpSet;
use log::info;
use regex::{self, Regex};
use std::{
    cell::Cell,
    collections::LinkedList,
    fs::File,
    io::{self, BufRead, BufReader},
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
    rules: Vec<Regex>,
    lru: Cell<Option<Regex>>,
}

impl Rules {
    fn new() -> Self {
        Rules {
            rules: Vec::with_capacity(2048),
            lru: Cell::new(None),
        }
    }

    pub fn add_rule(&mut self, rule: &str) {
        let _ = Regex::new(rule)
            .map_err(|err| {
                info!("rule {} failed {}", rule, err);

                err
            })
            .and_then(|re| {
                self.rules.push(re);

                Ok(())
            });
    }

    pub fn is_match(&self, m: &str) -> bool {
        unsafe {
            if let Some(ref re) = *(self.lru.as_ptr()) {
                if re.is_match(m) {
                    return true;
                }
            }
        }

        for rule in self.rules.iter() {
            if rule.is_match(m) {
                self.lru.set(Some(rule.clone()));

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
        let mut line = String::with_capacity(512);
        let mut rules: Option<&mut Rules> = None;
        let mut count: usize = 0;

        let pat: &[_] = &[' ', '\t', '\r', '\n'];
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
                // list_ipv4 = &outbound_block_list_ipv4;
                // list_ipv6 = &outbound_block_list_ipv6;
                rules = Some(&mut self.outbound_block_list_rules);
                continue;
            } else if l.starts_with("[black_list]") || l.starts_with("[bypass_list]") {
                // list_ipv4 = &black_list_ipv4;
                // list_ipv6 = &black_list_ipv6;
                rules = Some(&mut self.black_list_rules);
                continue;
            } else if l.starts_with("[white_list]") || l.starts_with("[proxy_list]") {
                // list_ipv4 = &white_list_ipv4;
                // list_ipv6 = &white_list_ipv6;
                rules = Some(&mut self.white_list_rules);
                continue;
            } else if l.starts_with("[reject_all]") || l.starts_with("[bypass_all]") {
                // acl_mode = WHITE_LIST;
                continue;
            } else if l.starts_with("[accept_all]") || l.starts_with("[proxy_all]") {
                // acl_mode = BLACK_LIST;
                continue;
            }

            if let Some(ref mut r) = rules {
                count += 1;
                r.add_rule(l);
            }
        }

        info!("rules {}", count);
        Ok(())
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
