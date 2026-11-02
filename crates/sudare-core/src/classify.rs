//! Internal / public / reserved scope. Uses explicit lists rather than
//! `IpAddr::is_private` so documentation ranges are never mistaken for private ones.

use crate::types::{Entity, EntityType, Scope};
use ipnet::IpNet;
use std::net::IpAddr;

const INTERNAL_NETS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fe80::/10",
    "fc00::/7",
];
const DOCUMENTATION_NETS: &[&str] = &[
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "2001:db8::/32",
];
const RESERVED_NETS: &[&str] = &[
    "0.0.0.0/8",
    "192.0.0.0/24",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "100::/64",
    "ff00::/8",
];
/// Suffixes that never resolve on the public internet.
pub const INTERNAL_SUFFIXES: &[&str] = &[
    "local",
    "internal",
    "lan",
    "home.arpa",
    "localdomain",
    "intranet",
    "corp",
    "private",
    "localhost",
];

fn nets(list: &[&str]) -> Vec<IpNet> {
    list.iter().filter_map(|n| n.parse().ok()).collect()
}

#[derive(Debug, Clone)]
pub struct Classifier {
    internal: Vec<IpNet>,
    documentation: Vec<IpNet>,
    reserved: Vec<IpNet>,
    domains: Vec<String>,
    documentation_public: bool,
}

impl Classifier {
    pub fn new(extra_networks: &[IpNet], extra_domains: &[String]) -> Self {
        let mut internal = extra_networks.to_vec();
        internal.extend(nets(INTERNAL_NETS));
        Self {
            internal,
            documentation: nets(DOCUMENTATION_NETS),
            reserved: nets(RESERVED_NETS),
            domains: extra_domains
                .iter()
                .map(|d| d.trim_matches('.').to_ascii_lowercase())
                .collect(),
            documentation_public: false,
        }
    }

    /// Test fixtures use documentation ranges to stand in for public addresses.
    /// Only those ranges are promoted; RFC 1918 and the rest keep their scope.
    #[doc(hidden)]
    pub fn documentation_ranges_public(mut self) -> Self {
        self.documentation_public = true;
        self
    }

    /// Learn the parent domain of a host the log source names as itself,
    /// e.g. `dc01.corp.example.com` → `corp.example.com`.
    pub fn learn_domain(&mut self, host: &str) {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.parse::<IpAddr>().is_ok() {
            return;
        }
        let labels: Vec<&str> = host.split('.').collect();
        // Need host.domain.tld at least, so we never learn a bare TLD or public apex.
        if labels.len() < 3 || labels.iter().any(|l| l.is_empty()) {
            return;
        }
        let parent = labels[1..].join(".");
        if !self.domains.contains(&parent) {
            self.domains.push(parent);
        }
    }

    pub fn ip(&self, ip: IpAddr) -> Scope {
        let ip = ip.to_canonical();
        if self.internal.iter().any(|n| n.contains(&ip)) {
            return Scope::Internal;
        }
        if self.documentation.iter().any(|n| n.contains(&ip)) {
            return if self.documentation_public {
                Scope::Public
            } else {
                Scope::Reserved
            };
        }
        if self.reserved.iter().any(|n| n.contains(&ip)) || ip.is_multicast() || ip.is_unspecified()
        {
            return Scope::Reserved;
        }
        if let IpAddr::V4(v4) = ip
            && v4.is_broadcast()
        {
            return Scope::Reserved;
        }
        Scope::Public
    }

    pub fn host(&self, host: &str) -> Scope {
        let host = host.trim_matches(|c| c == '[' || c == ']');
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.ip(ip);
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !host.contains('.') {
            return Scope::Internal;
        }
        let internal = INTERNAL_SUFFIXES
            .iter()
            .map(|s| s.to_string())
            .chain(self.domains.iter().cloned())
            .any(|d| host == d || host.ends_with(&format!(".{d}")));
        if internal {
            Scope::Internal
        } else {
            Scope::Public
        }
    }

    pub fn scope(&self, e: &Entity) -> Scope {
        match &e.kind {
            EntityType::Ip => e
                .normalized
                .parse::<IpAddr>()
                .map(|ip| self.ip(ip))
                .unwrap_or(Scope::Internal),
            EntityType::Hostname | EntityType::Username => Scope::Internal,
            EntityType::Fqdn => self.host(&e.normalized),
            EntityType::Url => match url::Url::parse(&e.value) {
                Ok(u) => u
                    .host_str()
                    .map(|h| self.host(h))
                    .unwrap_or(Scope::Internal),
                // Fail closed: an unparsable URL is treated as internal.
                Err(_) => Scope::Internal,
            },
            EntityType::Email => match e.normalized.rsplit_once('@') {
                Some((_, domain)) => self.host(domain),
                None => Scope::Internal,
            },
            _ => Scope::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_scopes() {
        let c = Classifier::new(&[], &[]);
        assert_eq!(c.ip("10.1.2.3".parse().unwrap()), Scope::Internal);
        assert_eq!(c.ip("192.0.2.1".parse().unwrap()), Scope::Reserved);
        assert_eq!(c.ip("8.8.8.8".parse().unwrap()), Scope::Public);
        assert_eq!(c.ip("::ffff:10.0.0.1".parse().unwrap()), Scope::Internal);
        let c = c.documentation_ranges_public();
        assert_eq!(c.ip("198.51.100.7".parse().unwrap()), Scope::Public);
        assert_eq!(c.ip("10.0.0.1".parse().unwrap()), Scope::Internal);
    }

    #[test]
    fn host_scopes_and_learning() {
        let mut c = Classifier::new(&[], &[]);
        assert_eq!(c.host("fw01"), Scope::Internal);
        assert_eq!(c.host("printer.local"), Scope::Internal);
        assert_eq!(c.host("app.corp.example.com"), Scope::Public);
        c.learn_domain("dc01.corp.example.com");
        assert_eq!(c.host("app.corp.example.com"), Scope::Internal);
        assert_eq!(c.host("example.org"), Scope::Public);
        c.learn_domain("example.org"); // too short to learn
        assert_eq!(c.host("cdn.example.org"), Scope::Public);
    }
}
