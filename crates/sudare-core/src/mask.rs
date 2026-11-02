//! Reversible masking. Every masked value becomes a typed token such as
//! `[[IP_INTERNAL_412]]`: one token per value for the whole analysis and its chat,
//! numbered by a salted HMAC so the numbers leak neither order nor count.

use crate::extract::{self, Extractor, whole_word};
use crate::parse::Parser;
use crate::policy::{Action, Mode, Policy, PolicyError};
use crate::types::{Entity, EntityType, Event, Scope, Source, Span};
use aho_corasick::{AhoCorasick, MatchKind};
use hmac::{Hmac, KeyInit, Mac};
use regex::Regex;
use serde::Serialize;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use zeroize::Zeroize;

pub const BUILTIN_PREFIXES: &[&str] = &[
    "IP_INTERNAL",
    "IP_PUBLIC",
    "IP_RESERVED",
    "HOST",
    "FQDN_INTERNAL",
    "FQDN_PUBLIC",
    "URL_INTERNAL",
    "URL_PUBLIC",
    "URL_RESERVED",
    "EMAIL",
    "USER",
    "MAC",
    "PATH",
    "PROCESS",
    "HASH_MD5",
    "HASH_SHA1",
    "HASH_SHA256",
    "CVE",
    "SECRET",
    "LITERAL",
    "SID",
    "TERM",
    "REDACTED",
];

pub fn prefix(kind: &EntityType, scope: Scope) -> String {
    use EntityType::*;
    match (kind, scope) {
        (Ip, Scope::Internal) => "IP_INTERNAL".into(),
        (Ip, Scope::Public) => "IP_PUBLIC".into(),
        (Ip, _) => "IP_RESERVED".into(),
        (Hostname, _) => "HOST".into(),
        (Fqdn, Scope::Public) => "FQDN_PUBLIC".into(),
        (Fqdn, _) => "FQDN_INTERNAL".into(),
        (Url, Scope::Public) => "URL_PUBLIC".into(),
        (Url, Scope::Reserved) => "URL_RESERVED".into(),
        (Url, _) => "URL_INTERNAL".into(),
        (Email, _) => "EMAIL".into(),
        (Username, _) => "USER".into(),
        (Mac, _) => "MAC".into(),
        (FilePath, _) => "PATH".into(),
        (Process, _) => "PROCESS".into(),
        (Md5, _) => "HASH_MD5".into(),
        (Sha1, _) => "HASH_SHA1".into(),
        (Sha256, _) => "HASH_SHA256".into(),
        (Cve, _) => "CVE".into(),
        (Secret, _) => "SECRET".into(),
        (Literal, _) => "LITERAL".into(),
        (Custom(n), _) => n.to_ascii_uppercase(),
    }
}

struct MapEntry {
    original: String,
    normalized: String,
    kind: EntityType,
    scope: Scope,
}

/// Token ↔ real value for one analysis. Zeroed on drop, never serialized in clear,
/// and its `Debug` output shows only counts.
pub struct MaskMap {
    salt: [u8; 32],
    by_value: HashMap<(String, String), String>,
    entries: BTreeMap<String, MapEntry>,
    used: HashMap<String, HashSet<u32>>,
    /// Built on first unmask; reset when a new prefix (a custom rule) appears.
    token_re: std::sync::OnceLock<Regex>,
}

impl std::fmt::Debug for MaskMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaskMap({} tokens)", self.entries.len())
    }
}

impl Drop for MaskMap {
    fn drop(&mut self) {
        self.salt.zeroize();
        for ((mut p, mut n), mut t) in self.by_value.drain() {
            p.zeroize();
            n.zeroize();
            t.zeroize();
        }
        while let Some((mut t, mut e)) = self.entries.pop_first() {
            t.zeroize();
            e.original.zeroize();
            e.normalized.zeroize();
        }
    }
}

pub struct Unmasked {
    pub text: String,
    /// Token-shaped strings in the text that this map does not know.
    pub unknown: Vec<String>,
}

impl MaskMap {
    pub fn new(salt: [u8; 32]) -> Self {
        Self {
            salt,
            by_value: HashMap::new(),
            entries: BTreeMap::new(),
            used: HashMap::new(),
            token_re: std::sync::OnceLock::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Real value behind a token. For local display only.
    pub fn original(&self, token: &str) -> Option<&str> {
        self.entries.get(token).map(|e| e.original.as_str())
    }

    pub fn tokens(&self) -> impl Iterator<Item = (&str, &EntityType, Scope)> {
        self.entries
            .iter()
            .map(|(t, e)| (t.as_str(), &e.kind, e.scope))
    }

    pub(crate) fn token_of(&self, prefix: &str, normalized: &str) -> Option<&str> {
        self.by_value
            .get(&(prefix.to_string(), normalized.to_string()))
            .map(String::as_str)
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.salt)
            .expect("HMAC takes any key length");
        for p in parts {
            m.update(p);
            m.update(&[0]);
        }
        m.finalize().into_bytes().into()
    }

    /// Per-analysis random marker for prompt delimiters.
    pub(crate) fn nonce(&self) -> String {
        self.mac(&[b"prompt-delimiter"])[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn assign(
        &mut self,
        prefix: &str,
        normalized: &str,
        original: &str,
        kind: &EntityType,
        scope: Scope,
        expected: usize,
    ) -> String {
        if let Some(t) = self.token_of(prefix, normalized) {
            return t.to_string();
        }
        let digest = self.mac(&[prefix.as_bytes(), normalized.as_bytes()]);
        if !self.used.contains_key(prefix) && !BUILTIN_PREFIXES.contains(&prefix) {
            self.token_re = std::sync::OnceLock::new();
        }
        let used = self.used.entry(prefix.to_string()).or_default();
        // Sparse numbering with 10x headroom: the number says nothing about how many
        // values exist or where they appeared.
        let range = (expected.max(used.len() + 1) * 10).max(100) as u64;
        let mut n =
            (u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) % range) as u32 + 1;
        while used.contains(&n) {
            n = n % range as u32 + 1;
        }
        used.insert(n);
        let token = format!("[[{prefix}_{n}]]");
        self.by_value
            .insert((prefix.to_string(), normalized.to_string()), token.clone());
        self.entries.insert(
            token.clone(),
            MapEntry {
                original: original.to_string(),
                normalized: normalized.to_string(),
                kind: kind.clone(),
                scope,
            },
        );
        token
    }

    fn prefixes(&self) -> BTreeSet<String> {
        let mut p: BTreeSet<String> = BUILTIN_PREFIXES.iter().map(|s| s.to_string()).collect();
        for t in self.entries.keys() {
            if let Some(inner) = t.strip_prefix("[[").and_then(|t| t.strip_suffix("]]"))
                && let Some((pfx, _)) = inner.rsplit_once('_')
            {
                p.insert(pfx.to_string());
            }
        }
        p
    }

    /// Shared regex when only built-in prefixes are in use; per-map when a custom rule adds one.
    fn token_regex(&self) -> &Regex {
        static BUILTIN: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            token_regex(BUILTIN_PREFIXES.iter().map(|s| s.to_string()))
        });
        if self
            .used
            .keys()
            .all(|p| BUILTIN_PREFIXES.contains(&p.as_str()))
        {
            return &BUILTIN;
        }
        self.token_re
            .get_or_init(|| token_regex(self.prefixes().into_iter()))
    }

    /// Canonical `[[P_N]]` for a tolerant token, if the whole string is one.
    pub fn canonical_token(&self, s: &str) -> Option<String> {
        let s = s.trim();
        let re = self.token_regex();
        let c = re.captures(s)?;
        if c.get(0)?.len() != s.len() {
            return None;
        }
        let token = canonical(&c)?;
        self.entries.contains_key(&token).then_some(token)
    }

    pub fn unmask(&self, text: &str) -> Unmasked {
        let re = self.token_regex();
        let mut unknown = Vec::new();
        let out = re.replace_all(text, |c: &regex::Captures| {
            let whole = c.get(0).map_or("", |m| m.as_str()).to_string();
            match canonical(c) {
                Some(t) if t.starts_with("[[REDACTED_") => whole,
                Some(t) => match self.entries.get(&t) {
                    Some(e) => e.original.clone(),
                    None => {
                        unknown.push(whole.clone());
                        whole
                    }
                },
                None => whole,
            }
        });
        Unmasked {
            text: out.into_owned(),
            unknown,
        }
    }
}

/// Exact `[[P_N]]` first; then tolerant forms models produce: other case, inner
/// spaces, one bracket or none (`[[ host 5 ]]`, `[HOST_5]`, `HOST_5`).
fn token_regex(prefixes: impl Iterator<Item = String>) -> Regex {
    let mut ps: Vec<String> = prefixes.collect();
    ps.sort_by_key(|p| std::cmp::Reverse(p.len()));
    let loose = ps
        .iter()
        .map(|p| regex::escape(p).replace('_', "[_ ]"))
        .collect::<Vec<_>>()
        .join("|");
    let strict = ps
        .iter()
        .map(|p| regex::escape(p))
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&format!(
        r"(?i)\[\[\s*({loose})[_ ]?(\d{{1,6}})\s*\]\]|\[\s*({strict})_(\d{{1,6}})\s*\]|\b({strict})_(\d{{1,6}})\b"
    ))
    .expect("token regex")
}

fn canonical(c: &regex::Captures) -> Option<String> {
    let (p, n) = [(1, 2), (3, 4), (5, 6)]
        .iter()
        .find_map(|&(a, b)| Some((c.get(a)?, c.get(b)?)))?;
    let p = p.as_str().to_ascii_uppercase().replace(' ', "_");
    let n: u32 = n.as_str().parse().ok()?;
    Some(format!("[[{p}_{n}]]"))
}

/// Text that went through the masker. The only way to get one is from this crate.
#[derive(Debug, Clone)]
pub struct MaskedText(pub(crate) String);

impl MaskedText {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MaskedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EventRef {
    pub lines: (u32, u32),
    pub group: Option<String>,
}

/// The masked log text plus line/event metadata. Holds no real values.
#[derive(Debug, Clone)]
pub struct MaskedInput {
    pub(crate) text: String,
    pub(crate) lines: u32,
    pub(crate) events: Vec<EventRef>,
}

impl MaskedInput {
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn line_count(&self) -> u32 {
        self.lines
    }
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    Ip,
    Domain,
    Url,
    Hash,
}

/// A value that may be sent to a threat-intel provider. Built only from public-scope
/// IPs, domains and URLs (and hashes with hash context) whose text contains no
/// masked value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicIndicator {
    kind: IndicatorKind,
    value: String,
    token: Option<String>,
}

impl PublicIndicator {
    pub fn kind(&self) -> IndicatorKind {
        self.kind
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    /// The token standing in for this value in the prompt, when it was masked (strict mode).
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }
    #[doc(hidden)]
    pub fn for_tests(kind: IndicatorKind, value: &str) -> Self {
        Self {
            kind,
            value: value.into(),
            token: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MaskStats {
    /// Masked occurrences per token prefix.
    pub masked: BTreeMap<String, usize>,
    /// Distinct masked values per token prefix.
    pub distinct: BTreeMap<String, usize>,
    pub dropped: usize,
    pub kept: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub entity: Entity,
    pub action: Action,
    pub token: Option<String>,
}

pub(crate) struct Applied {
    pub text: String,
    pub stats: MaskStats,
    pub indicators: Vec<PublicIndicator>,
    pub decisions: Vec<Decision>,
}

pub struct Masker {
    policy: Policy,
    rules: Vec<(String, Regex, Action)>,
    deny: Option<AhoCorasick>,
    allow: HashSet<String>,
    literal: Regex,
}

impl Masker {
    pub fn new(policy: Policy) -> Result<Self, PolicyError> {
        let rules = policy
            .rules
            .iter()
            .map(|r| {
                let re = regex::RegexBuilder::new(&r.pattern)
                    .size_limit(1 << 20)
                    .build()
                    .map_err(|e| PolicyError::Rule {
                        name: r.name.clone(),
                        reason: e.to_string(),
                    })?;
                Ok((r.name.to_ascii_uppercase(), re, r.action))
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;
        let deny_terms: Vec<&String> = policy.deny.iter().filter(|t| !t.is_empty()).collect();
        let deny = (!deny_terms.is_empty()).then(|| {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostLongest)
                .build(&deny_terms)
                .expect("denylist automaton")
        });
        let mut prefixes: Vec<String> = BUILTIN_PREFIXES.iter().map(|s| s.to_string()).collect();
        prefixes.extend(rules.iter().map(|r| r.0.clone()));
        prefixes.sort_by_key(|p| std::cmp::Reverse(p.len()));
        let alt = prefixes
            .iter()
            .map(|p| regex::escape(p))
            .collect::<Vec<_>>()
            .join("|");
        // Token-shaped input can't be allowed to pose as a token.
        let literal = Regex::new(&format!(
            r"(?i)\[\[[^\[\]\n]{{0,64}}\]\]|\[?\b(?:{alt})_\d{{1,6}}\b\]?"
        ))
        .expect("literal regex");
        let allow = policy.allow.iter().cloned().collect();
        Ok(Self {
            policy,
            rules,
            deny,
            allow,
            literal,
        })
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub(crate) fn extractors<'a>(&'a self, parser: &'a dyn Parser) -> Vec<Box<dyn Extractor + 'a>> {
        vec![
            Box::new(extract::RegexExtractor),
            Box::new(extract::SecretExtractor),
            Box::new(extract::FieldExtractor { parser }),
            Box::new(PolicyExtractor { m: self }),
        ]
    }

    fn decide(&self, e: &Entity) -> Action {
        let strict = self.policy.mode == Mode::Strict;
        if matches!(e.source, Source::Denylist)
            || matches!(e.kind, EntityType::Secret | EntityType::Literal)
        {
            return Action::Mask;
        }
        if self
            .policy
            .deny
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&e.value))
        {
            return Action::Mask;
        }
        if !strict && self.allow.contains(&e.value.to_lowercase()) {
            return Action::Keep;
        }
        if strict {
            return Action::Mask;
        }
        if let Source::Rule(name) = &e.source {
            return self
                .rules
                .iter()
                .find(|r| &r.0 == name)
                .map_or(Action::Mask, |r| r.2);
        }
        self.policy.type_action(e)
    }

    pub(crate) fn apply(&self, text: &str, entities: Vec<Entity>, map: &mut MaskMap) -> Applied {
        // 1. Decide, dropping duplicates of the same kind at the same span.
        let mut seen = HashSet::new();
        let mut items: Vec<(Entity, Action)> = entities
            .into_iter()
            .filter(|e| !e.span.is_empty() && e.span.end <= text.len())
            .filter(|e| seen.insert((e.span, e.kind.clone())))
            .map(|e| {
                let a = self.decide(&e);
                (e, a)
            })
            .collect();

        // 2. Mask every other occurrence of a masked value, and of values masked
        //    earlier in this analysis (chat follow-ups reuse the same map).
        struct Template {
            kind: EntityType,
            scope: Scope,
            normalized: String,
            action: Action,
        }
        let mut needles: Vec<String> = Vec::new();
        let mut templates: Vec<Template> = Vec::new();
        let mut needle_seen = HashSet::new();
        for (e, a) in &items {
            if *a != Action::Keep
                && e.kind != EntityType::Literal
                && e.value.chars().count() >= 3
                && needle_seen.insert(e.value.to_lowercase())
            {
                needles.push(e.value.clone());
                templates.push(Template {
                    kind: e.kind.clone(),
                    scope: e.scope,
                    normalized: e.normalized.clone(),
                    action: *a,
                });
            }
        }
        for m in map.entries.values() {
            if m.kind != EntityType::Literal
                && m.original.chars().count() >= 3
                && needle_seen.insert(m.original.to_lowercase())
            {
                needles.push(m.original.clone());
                templates.push(Template {
                    kind: m.kind.clone(),
                    scope: m.scope,
                    normalized: m.normalized.clone(),
                    action: Action::Mask,
                });
            }
        }
        if !needles.is_empty() {
            let spans: HashSet<Span> = items.iter().map(|(e, _)| e.span).collect();
            let ac = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostLongest)
                .build(&needles)
                .expect("propagation automaton");
            for m in ac.find_iter(text) {
                let span = Span::new(m.start(), m.end());
                if spans.contains(&span) || !whole_word(text, span.start, span.end) {
                    continue;
                }
                let t = &templates[m.pattern().as_usize()];
                let entity = Entity {
                    kind: t.kind.clone(),
                    value: text[span.start..span.end].to_string(),
                    normalized: t.normalized.clone(),
                    span,
                    scope: t.scope,
                    source: Source::Propagated,
                };
                items.push((entity, t.action));
            }
        }

        // 3. Merge overlapping masked spans outward; the longest entity names the group.
        let mut order: Vec<usize> = (0..items.len())
            .filter(|&i| items[i].1 != Action::Keep)
            .collect();
        order.sort_by_key(|&i| {
            (
                items[i].0.span.start,
                std::cmp::Reverse(items[i].0.span.len()),
            )
        });
        let mut groups: Vec<(Span, usize, Action)> = Vec::new();
        for i in order {
            let (sp, a) = (items[i].0.span, items[i].1);
            match groups.last_mut() {
                Some(g) if sp.start < g.0.end => {
                    g.0 = Span::new(g.0.start, g.0.end.max(sp.end));
                    if sp.len() > items[g.1].0.span.len() {
                        g.1 = i;
                    }
                    if a == Action::Mask {
                        g.2 = Action::Mask;
                    }
                }
                _ => groups.push((sp, i, a)),
            }
        }

        // 4. Token per group. Count distinct values per prefix first for the range.
        let label = |g: &(Span, usize, Action)| {
            let rep = &items[g.1].0;
            let pfx = prefix(&rep.kind, rep.scope);
            if g.0 == rep.span {
                (
                    pfx,
                    rep.normalized.clone(),
                    rep.value.clone(),
                    rep.kind.clone(),
                    rep.scope,
                )
            } else {
                let t = &text[g.0.start..g.0.end];
                (
                    pfx,
                    t.to_ascii_lowercase(),
                    t.to_string(),
                    rep.kind.clone(),
                    rep.scope,
                )
            }
        };
        let labels: Vec<_> = groups.iter().map(label).collect();
        let mut expected: HashMap<&str, HashSet<&str>> = HashMap::new();
        for l in &labels {
            expected
                .entry(l.0.as_str())
                .or_default()
                .insert(l.1.as_str());
        }
        let expected: HashMap<String, usize> = expected
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.len()))
            .collect();

        let mut out = String::with_capacity(text.len());
        let mut stats = MaskStats::default();
        let mut last = 0;
        for (g, (pfx, norm, orig, kind, scope)) in groups.iter().zip(&labels) {
            out.push_str(&text[last..g.0.start]);
            if g.2 == Action::Drop {
                out.push_str(&format!("[[REDACTED_{pfx}]]"));
                stats.dropped += 1;
            } else {
                let token = map.assign(pfx, norm, orig, kind, *scope, expected[pfx]);
                out.push_str(&token);
                *stats.masked.entry(pfx.clone()).or_default() += 1;
            }
            // Keep line numbers stable when a masked value (a PEM key) spans lines.
            out.push_str(&"\n".repeat(text[g.0.start..g.0.end].matches('\n').count()));
            last = g.0.end;
        }
        out.push_str(&text[last..]);
        for (pfx, norm, ..) in &labels {
            if map.token_of(pfx, norm).is_some() {
                stats.distinct.insert(pfx.clone(), 0);
            }
        }
        for (pfx, n) in stats.distinct.iter_mut() {
            *n = map.by_value.keys().filter(|(p, _)| p == pfx).count();
        }

        // 5. Decisions (one per distinct value) and threat-intel eligible indicators.
        let masked_values: Vec<String> = map
            .entries
            .values()
            .map(|e| e.original.to_lowercase())
            .filter(|v| v.chars().count() >= 3)
            .collect();
        let mut decisions = Vec::new();
        let mut indicators = Vec::new();
        let mut decided = HashSet::new();
        let mut ind_seen = HashSet::new();
        for (e, a) in &items {
            let pfx = prefix(&e.kind, e.scope);
            if !decided.insert((pfx.clone(), e.normalized.clone())) {
                continue;
            }
            if *a == Action::Keep {
                stats.kept += 1;
            }
            let token = map.token_of(&pfx, &e.normalized).map(str::to_string);
            decisions.push(Decision {
                entity: e.clone(),
                action: *a,
                token: token.clone(),
            });

            let kind = match (&e.kind, e.scope) {
                (EntityType::Ip, Scope::Public) => IndicatorKind::Ip,
                (EntityType::Fqdn, Scope::Public) => IndicatorKind::Domain,
                (EntityType::Url, Scope::Public) => IndicatorKind::Url,
                (EntityType::Md5 | EntityType::Sha1 | EntityType::Sha256, _)
                    if !matches!(e.source, Source::Regex) =>
                {
                    IndicatorKind::Hash
                }
                _ => continue,
            };
            let lower = e.value.to_lowercase();
            let holds_masked = masked_values
                .iter()
                .any(|m| *m != lower && lower.contains(m.as_str()))
                || groups
                    .iter()
                    .any(|g| e.span.contains(&g.0) && g.0 != e.span);
            if holds_masked {
                continue;
            }
            let value = match kind {
                IndicatorKind::Url => e.value.clone(),
                _ => e.normalized.clone(),
            };
            if ind_seen.insert((kind, value.clone())) {
                indicators.push(PublicIndicator { kind, value, token });
            }
        }

        Applied {
            text: out,
            stats,
            indicators,
            decisions,
        }
    }
}

/// Custom rules, denylist terms and token-shaped literals.
struct PolicyExtractor<'a> {
    m: &'a Masker,
}

impl Extractor for PolicyExtractor<'_> {
    fn name(&self) -> &str {
        "policy"
    }

    fn extract(&self, text: &str, _: &[Event], out: &mut Vec<Entity>) {
        for (name, re, _) in &self.m.rules {
            for m in re.find_iter(text).filter(|m| !m.is_empty()) {
                out.push(Entity::new(
                    EntityType::Custom(name.clone()),
                    text,
                    Span::new(m.start(), m.end()),
                    Source::Rule(name.clone()),
                ));
            }
        }
        if let Some(ac) = &self.m.deny {
            for m in ac.find_iter(text) {
                if whole_word(text, m.start(), m.end()) {
                    out.push(Entity::new(
                        EntityType::Custom("TERM".into()),
                        text,
                        Span::new(m.start(), m.end()),
                        Source::Denylist,
                    ));
                }
            }
        }
        for m in self.m.literal.find_iter(text) {
            out.push(Entity::new(
                EntityType::Literal,
                text,
                Span::new(m.start(), m.end()),
                Source::Regex,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_numbers_are_stable_and_sparse() {
        let mut a = MaskMap::new([7; 32]);
        let t1 = a.assign(
            "HOST",
            "fw01",
            "fw01",
            &EntityType::Hostname,
            Scope::Internal,
            1,
        );
        let t2 = a.assign(
            "HOST",
            "fw01",
            "FW01",
            &EntityType::Hostname,
            Scope::Internal,
            1,
        );
        assert_eq!(t1, t2);
        let mut b = MaskMap::new([8; 32]);
        let t3 = b.assign(
            "HOST",
            "fw01",
            "fw01",
            &EntityType::Hostname,
            Scope::Internal,
            1,
        );
        // Different salt, (almost certainly) different number.
        assert!(t1.starts_with("[[HOST_") && t3.starts_with("[[HOST_"));
    }

    #[test]
    fn tolerant_unmask_and_unknown_tokens() {
        let mut m = MaskMap::new([1; 32]);
        let t = m.assign(
            "IP_INTERNAL",
            "10.0.0.1",
            "10.0.0.1",
            &EntityType::Ip,
            Scope::Internal,
            1,
        );
        let n = t
            .trim_start_matches("[[IP_INTERNAL_")
            .trim_end_matches("]]");
        let text = format!(
            "{t} [[ ip internal {n} ]] [IP_INTERNAL_{n}] IP_INTERNAL_{n} [[HOST_99999]] [[REDACTED_USER]]"
        );
        let u = m.unmask(&text);
        assert_eq!(
            u.text,
            "10.0.0.1 10.0.0.1 10.0.0.1 10.0.0.1 [[HOST_99999]] [[REDACTED_USER]]"
        );
        assert_eq!(u.unknown, vec!["[[HOST_99999]]".to_string()]);
        assert_eq!(m.canonical_token(&format!("[[ip_internal_{n}]]")), Some(t));
    }

    #[test]
    fn debug_never_prints_values() {
        let mut m = MaskMap::new([1; 32]);
        m.assign(
            "USER",
            "jdoe",
            "jdoe",
            &EntityType::Username,
            Scope::Internal,
            1,
        );
        assert_eq!(format!("{m:?}"), "MaskMap(1 tokens)");
    }
}
