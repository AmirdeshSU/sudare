//! Masking policy, loaded from TOML. See `policy.example.toml`.
//!
//! Precedence for each entity: denylist > secret/literal > allowlist > rule > type action.
//! Strict mode masks every type and ignores the allowlist.

use crate::types::{Entity, EntityType, Scope};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Default,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Mask,
    Keep,
    Drop,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    pub mode: Mode,
    pub classify: Classify,
    pub actions: Actions,
    pub rules: Vec<Rule>,
    pub lists: Lists,
    /// Lowercased allowlist entries, loaded from `lists.allow`.
    #[serde(skip)]
    pub allow: Vec<String>,
    /// Denylist terms, loaded from `lists.deny`.
    #[serde(skip)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Classify {
    pub internal_networks: Vec<String>,
    pub internal_domains: Vec<String>,
    pub learn_internal_domains: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scoped {
    pub internal: Action,
    pub public: Action,
    pub reserved: Action,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Actions {
    pub ip: Scoped,
    pub fqdn: Scoped,
    pub url: Scoped,
    pub hostname: Action,
    pub email: Action,
    pub username: Action,
    pub mac: Action,
    pub hash: Action,
    pub file_path: Action,
    pub process: Action,
    pub cve: Action,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub pattern: String,
    #[serde(default = "mask")]
    pub action: Action,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Lists {
    pub allow: Option<PathBuf>,
    pub deny: Option<PathBuf>,
}

fn mask() -> Action {
    Action::Mask
}

impl Default for Classify {
    fn default() -> Self {
        Self {
            internal_networks: Vec::new(),
            internal_domains: Vec::new(),
            learn_internal_domains: true,
        }
    }
}

impl Default for Scoped {
    fn default() -> Self {
        Self {
            internal: Action::Mask,
            public: Action::Keep,
            reserved: Action::Keep,
        }
    }
}

impl Default for Actions {
    fn default() -> Self {
        Self {
            ip: Scoped::default(),
            fqdn: Scoped::default(),
            url: Scoped::default(),
            hostname: Action::Mask,
            email: Action::Mask,
            username: Action::Mask,
            mac: Action::Mask,
            hash: Action::Keep,
            file_path: Action::Keep,
            process: Action::Keep,
            cve: Action::Keep,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Default,
            classify: Classify::default(),
            actions: Actions::default(),
            rules: Vec::new(),
            lists: Lists::default(),
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy file: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("internal_networks entry {0:?} is not a CIDR network")]
    Network(String),
    #[error("rule {name:?}: {reason}")]
    Rule { name: String, reason: String },
}

impl Policy {
    pub fn from_toml(s: &str) -> Result<Self, PolicyError> {
        let p: Policy = toml::from_str(s)?;
        p.validate()?;
        Ok(p)
    }

    /// Load a policy file; `lists.allow` / `lists.deny` resolve relative to it.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let read = |p: &Path| {
            std::fs::read_to_string(p).map_err(|source| PolicyError::Io {
                path: p.to_path_buf(),
                source,
            })
        };
        let mut p = Self::from_toml(&read(path)?)?;
        let dir = path.parent().unwrap_or(Path::new("."));
        if let Some(allow) = p.lists.allow.clone() {
            p.allow = list_entries(&read(&dir.join(allow))?)
                .map(|e| e.to_lowercase())
                .collect();
        }
        if let Some(deny) = p.lists.deny.clone() {
            p.deny = list_entries(&read(&dir.join(deny))?)
                .map(str::to_owned)
                .collect();
        }
        Ok(p)
    }

    pub fn strict(mut self) -> Self {
        self.mode = Mode::Strict;
        self
    }

    pub fn networks(&self) -> Result<Vec<ipnet::IpNet>, PolicyError> {
        self.classify
            .internal_networks
            .iter()
            .map(|n| n.parse().map_err(|_| PolicyError::Network(n.clone())))
            .collect()
    }

    fn validate(&self) -> Result<(), PolicyError> {
        self.networks()?;
        for r in &self.rules {
            let bad = |reason: &str| PolicyError::Rule {
                name: r.name.clone(),
                reason: reason.into(),
            };
            let ok_name = r.name.len() <= 32
                && r.name.starts_with(|c: char| c.is_ascii_alphabetic())
                && r.name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !ok_name {
                return Err(bad(
                    "name must be a letter then letters, digits or _ (max 32)",
                ));
            }
            if crate::mask::BUILTIN_PREFIXES.contains(&r.name.to_ascii_uppercase().as_str()) {
                return Err(bad("name clashes with a built-in token prefix"));
            }
            regex::RegexBuilder::new(&r.pattern)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| bad(&e.to_string()))?;
        }
        Ok(())
    }

    /// The action the policy's type table gives this entity.
    pub fn type_action(&self, e: &Entity) -> Action {
        use EntityType::*;
        let a = &self.actions;
        let scoped = |s: &Scoped| match e.scope {
            Scope::Public => s.public,
            Scope::Reserved => s.reserved,
            _ => s.internal,
        };
        match &e.kind {
            Ip => scoped(&a.ip),
            Fqdn => scoped(&a.fqdn),
            Url => scoped(&a.url),
            Hostname => a.hostname,
            Email => a.email,
            Username => a.username,
            Mac => a.mac,
            Md5 | Sha1 | Sha256 => a.hash,
            FilePath => a.file_path,
            Process => a.process,
            Cve => a.cve,
            Secret | Literal | Custom(_) => Action::Mask,
        }
    }
}

/// One entry per line; blank lines and `#` comments skipped.
fn list_entries(s: &str) -> impl Iterator<Item = &str> {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_policy() {
        let p = Policy::from_toml(include_str!("../../../policy.example.toml")).unwrap();
        assert_eq!(p.mode, Mode::Default);
        assert_eq!(p.actions.ip.internal, Action::Mask);
        assert_eq!(p.rules[0].name, "employee_id");
    }

    #[test]
    fn rejects_typos_and_bad_rules() {
        assert!(Policy::from_toml("[actions]\nhostnme = \"mask\"").is_err());
        assert!(Policy::from_toml("[[rules]]\nname = \"HOST\"\npattern = \"x\"").is_err());
        assert!(Policy::from_toml("[[rules]]\nname = \"ok\"\npattern = \"(\"").is_err());
        assert!(Policy::from_toml("[classify]\ninternal_networks = [\"nope\"]").is_err());
    }
}
