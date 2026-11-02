//! Bundled MITRE ATT&CK Enterprise index (id, name, revoked-by, deprecated), generated
//! by `scripts/update_attack_index.py`. ATT&CK® is a registered trademark of The MITRE
//! Corporation; the data is used under MITRE's terms of use (see NOTICE).

use std::collections::HashMap;
use std::sync::LazyLock;

static DATA: &str = include_str!("../data/attack-enterprise.tsv");

struct Entry {
    name: &'static str,
    revoked_by: Option<&'static str>,
    deprecated: bool,
}

pub struct AttackIndex {
    version: String,
    entries: HashMap<&'static str, Entry>,
}

pub enum Lookup {
    Current(String),
    /// Revoked; `successor` is the live technique that replaced it.
    Revoked {
        successor: String,
        name: String,
    },
    Deprecated(String),
    Unknown,
}

pub fn index() -> &'static AttackIndex {
    static INDEX: LazyLock<AttackIndex> = LazyLock::new(|| AttackIndex::parse(DATA));
    &INDEX
}

impl AttackIndex {
    fn parse(data: &'static str) -> Self {
        let mut version = String::from("unknown");
        let mut entries = HashMap::new();
        for line in data.lines() {
            if let Some(header) = line.strip_prefix("# MITRE ATT&CK Enterprise ") {
                version = header.split('.').take(2).collect::<Vec<_>>().join(".");
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            if let [id, name, revoked_by, deprecated] = cols[..] {
                entries.insert(
                    id,
                    Entry {
                        name,
                        revoked_by: (!revoked_by.is_empty()).then_some(revoked_by),
                        deprecated: deprecated == "1",
                    },
                );
            }
        }
        Self { version, entries }
    }

    /// e.g. `v20.0`
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn lookup(&self, id: &str) -> Lookup {
        let Some(e) = self.entries.get(id) else {
            return Lookup::Unknown;
        };
        if let Some(mut next) = e.revoked_by {
            // Follow revocation chains to the live technique.
            for _ in 0..5 {
                match self.entries.get(next) {
                    Some(n) if n.revoked_by.is_some() => next = n.revoked_by.unwrap_or(next),
                    Some(n) => {
                        return Lookup::Revoked {
                            successor: next.to_string(),
                            name: n.name.to_string(),
                        };
                    }
                    None => break,
                }
            }
            return Lookup::Unknown;
        }
        if e.deprecated {
            Lookup::Deprecated(e.name.to_string())
        } else {
            Lookup::Current(e.name.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        let i = index();
        assert!(i.version().starts_with('v'));
        assert!(matches!(i.lookup("T1059.001"), Lookup::Current(n) if n.contains("PowerShell")));
        assert!(
            matches!(i.lookup("T1002"), Lookup::Revoked { successor, .. } if successor == "T1560")
        );
        assert!(matches!(i.lookup("T9999"), Lookup::Unknown));
    }
}
