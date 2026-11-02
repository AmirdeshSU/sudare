//! Threat-intel lookups. Only [`PublicIndicator`]s are accepted, so private IPs,
//! internal hostnames, usernames and emails cannot reach a provider. Lookups only:
//! nothing is ever submitted. Providers run only when their key is set.

use crate::cache::Cache;
use crate::http::{EgressRequest, Http, send_with_retry};
use crate::llm::ApiKey;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use sudare_core::report::{EnrichmentResult, TiStatus, TiVerdict};
use sudare_core::{IndicatorKind, PublicIndicator};

#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    pub per_minute: u32,
    /// Lookups per analysis, so one big log can't burn a daily quota.
    pub per_run: usize,
}

#[async_trait]
pub trait Enricher: Send + Sync {
    fn name(&self) -> &str;
    fn kinds(&self) -> &[IndicatorKind];
    fn default_rate(&self) -> RateLimit;
    fn configured(&self) -> bool;
    async fn lookup(&self, ind: &PublicIndicator, http: &dyn Http) -> EnrichmentResult;
}

/// Values go into URL paths: allow only what IPs, domains and hashes contain.
fn path_safe(v: &str) -> bool {
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-'))
}

/// A JSON string or number as text.
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => "?".into(),
    }
}

fn verdict(r: &mut EnrichmentResult, v: TiVerdict, fact: String) {
    r.verdict = Some(v);
    r.facts = vec![fact];
}

async fn fetch(
    name: &str,
    http: &dyn Http,
    req: EgressRequest,
) -> Result<(u16, Value), EnrichmentResult> {
    match send_with_retry(http, req.timeout(Duration::from_secs(20)), 2).await {
        Err(e) => Err(EnrichmentResult::status(
            name,
            TiStatus::Error,
            e.to_string(),
        )),
        Ok(r) if r.status == 429 => Err(EnrichmentResult::status(
            name,
            TiStatus::SkippedQuota,
            "provider rate limit hit",
        )),
        Ok(r) if r.status == 401 || r.status == 403 => Err(EnrichmentResult::status(
            name,
            TiStatus::Error,
            "key rejected",
        )),
        Ok(r) => Ok((r.status, r.json().unwrap_or(Value::Null))),
    }
}

fn ok(name: &str) -> EnrichmentResult {
    EnrichmentResult {
        provider: name.into(),
        status: TiStatus::Ok,
        verdict: None,
        score: None,
        facts: Vec::new(),
        link: None,
        cached: false,
    }
}

macro_rules! provider {
    ($ty:ident, $name:literal, $kinds:expr, $per_minute:expr, $per_run:expr) => {
        pub struct $ty {
            key: Option<ApiKey>,
        }
        impl $ty {
            pub fn new(key: Option<ApiKey>) -> Self {
                Self { key }
            }
        }
        impl $ty {
            const NAME: &'static str = $name;
            const KINDS: &'static [IndicatorKind] = $kinds;
            fn rate() -> RateLimit {
                RateLimit {
                    per_minute: $per_minute,
                    per_run: $per_run,
                }
            }
        }
    };
}

provider!(
    VirusTotal,
    "virustotal",
    &[
        IndicatorKind::Ip,
        IndicatorKind::Domain,
        IndicatorKind::Hash
    ],
    4,
    4
);
provider!(AbuseIpDb, "abuseipdb", &[IndicatorKind::Ip], 30, 20);
provider!(
    Otx,
    "otx",
    &[
        IndicatorKind::Ip,
        IndicatorKind::Domain,
        IndicatorKind::Hash
    ],
    30,
    20
);
provider!(
    UrlHaus,
    "urlhaus",
    &[
        IndicatorKind::Url,
        IndicatorKind::Domain,
        IndicatorKind::Ip,
        IndicatorKind::Hash
    ],
    30,
    20
);
provider!(
    ThreatFox,
    "threatfox",
    &[
        IndicatorKind::Ip,
        IndicatorKind::Domain,
        IndicatorKind::Url,
        IndicatorKind::Hash
    ],
    30,
    20
);
provider!(GreyNoise, "greynoise", &[IndicatorKind::Ip], 10, 10);

#[async_trait]
impl Enricher for VirusTotal {
    fn name(&self) -> &str {
        Self::NAME
    }
    fn kinds(&self) -> &[IndicatorKind] {
        Self::KINDS
    }
    fn default_rate(&self) -> RateLimit {
        Self::rate()
    }
    fn configured(&self) -> bool {
        self.key.is_some()
    }

    async fn lookup(&self, ind: &PublicIndicator, http: &dyn Http) -> EnrichmentResult {
        let Some(key) = &self.key else {
            return EnrichmentResult::status(Self::NAME, TiStatus::SkippedNoKey, "no key");
        };
        let v = ind.value();
        let (api, gui) = match ind.kind() {
            IndicatorKind::Ip => ("ip_addresses", "ip-address"),
            IndicatorKind::Domain => ("domains", "domain"),
            IndicatorKind::Hash => ("files", "file"),
            IndicatorKind::Url => {
                return EnrichmentResult::status(
                    Self::NAME,
                    TiStatus::Error,
                    "URL lookups not supported",
                );
            }
        };
        if !path_safe(v) {
            return EnrichmentResult::status(Self::NAME, TiStatus::Error, "unsupported characters");
        }
        let req = EgressRequest::get(format!("https://www.virustotal.com/api/v3/{api}/{v}"))
            .header("x-apikey", key.expose());
        let (status, body) = match fetch(Self::NAME, http, req).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        if status == 404 {
            return EnrichmentResult::status(
                Self::NAME,
                TiStatus::NotFound,
                "not seen by VirusTotal",
            );
        }
        let stats = &body["data"]["attributes"]["last_analysis_stats"];
        let (Some(m), Some(s)) = (stats["malicious"].as_u64(), stats["suspicious"].as_u64()) else {
            return EnrichmentResult::status(
                Self::NAME,
                TiStatus::Error,
                format!("unexpected response (HTTP {status})"),
            );
        };
        let total: u64 = stats
            .as_object()
            .map_or(0, |o| o.values().filter_map(Value::as_u64).sum());
        let mut r = ok(Self::NAME);
        let v_ = if m >= 2 {
            TiVerdict::Malicious
        } else if m + s > 0 {
            TiVerdict::Suspicious
        } else {
            TiVerdict::Clean
        };
        verdict(&mut r, v_, format!("{}/{total} engines flag it", m + s));
        r.score = (total > 0).then(|| (m + s) as f64 / total as f64);
        r.link = Some(format!("https://www.virustotal.com/gui/{gui}/{v}"));
        r
    }
}

#[async_trait]
impl Enricher for AbuseIpDb {
    fn name(&self) -> &str {
        Self::NAME
    }
    fn kinds(&self) -> &[IndicatorKind] {
        Self::KINDS
    }
    fn default_rate(&self) -> RateLimit {
        Self::rate()
    }
    fn configured(&self) -> bool {
        self.key.is_some()
    }

    async fn lookup(&self, ind: &PublicIndicator, http: &dyn Http) -> EnrichmentResult {
        let Some(key) = &self.key else {
            return EnrichmentResult::status(Self::NAME, TiStatus::SkippedNoKey, "no key");
        };
        let url = url::Url::parse_with_params(
            "https://api.abuseipdb.com/api/v2/check",
            &[("ipAddress", ind.value()), ("maxAgeInDays", "90")],
        )
        .map(String::from)
        .unwrap_or_default();
        let (status, body) = match fetch(
            Self::NAME,
            http,
            EgressRequest::get(url).header("key", key.expose()),
        )
        .await
        {
            Ok(x) => x,
            Err(r) => return r,
        };
        let d = &body["data"];
        let Some(score) = d["abuseConfidenceScore"].as_u64() else {
            return EnrichmentResult::status(
                Self::NAME,
                TiStatus::Error,
                format!("unexpected response (HTTP {status})"),
            );
        };
        let reports = d["totalReports"].as_u64().unwrap_or(0);
        let mut r = ok(Self::NAME);
        let v_ = match score {
            75.. => TiVerdict::Malicious,
            25.. => TiVerdict::Suspicious,
            _ if reports == 0 => TiVerdict::Clean,
            _ => TiVerdict::Unknown,
        };
        let mut fact = format!("abuse confidence {score}%, {reports} reports in 90 days");
        if let Some(isp) = d["isp"].as_str() {
            fact.push_str(&format!(", ISP {isp}"));
        }
        verdict(&mut r, v_, fact);
        r.score = Some(score as f64 / 100.0);
        r.link = Some(format!("https://www.abuseipdb.com/check/{}", ind.value()));
        r
    }
}

#[async_trait]
impl Enricher for Otx {
    fn name(&self) -> &str {
        Self::NAME
    }
    fn kinds(&self) -> &[IndicatorKind] {
        Self::KINDS
    }
    fn default_rate(&self) -> RateLimit {
        Self::rate()
    }
    fn configured(&self) -> bool {
        self.key.is_some()
    }

    async fn lookup(&self, ind: &PublicIndicator, http: &dyn Http) -> EnrichmentResult {
        let Some(key) = &self.key else {
            return EnrichmentResult::status(Self::NAME, TiStatus::SkippedNoKey, "no key");
        };
        let v = ind.value();
        let (section, page) = match ind.kind() {
            IndicatorKind::Ip if v.contains(':') => ("IPv6", "ip"),
            IndicatorKind::Ip => ("IPv4", "ip"),
            IndicatorKind::Domain => ("domain", "domain"),
            IndicatorKind::Hash => ("file", "file"),
            IndicatorKind::Url => {
                return EnrichmentResult::status(
                    Self::NAME,
                    TiStatus::Error,
                    "URL lookups not supported",
                );
            }
        };
        if !path_safe(v) {
            return EnrichmentResult::status(Self::NAME, TiStatus::Error, "unsupported characters");
        }
        let req = EgressRequest::get(format!(
            "https://otx.alienvault.com/api/v1/indicators/{section}/{v}/general"
        ))
        .header("x-otx-api-key", key.expose());
        let (status, body) = match fetch(Self::NAME, http, req).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        if status == 404 {
            return EnrichmentResult::status(Self::NAME, TiStatus::NotFound, "not in OTX");
        }
        let Some(pulses) = body["pulse_info"]["count"].as_u64() else {
            return EnrichmentResult::status(
                Self::NAME,
                TiStatus::Error,
                format!("unexpected response (HTTP {status})"),
            );
        };
        let mut r = ok(Self::NAME);
        let v_ = if pulses > 0 {
            TiVerdict::Suspicious
        } else {
            TiVerdict::Unknown
        };
        verdict(&mut r, v_, format!("in {pulses} OTX pulse(s)"));
        r.link = Some(format!("https://otx.alienvault.com/indicator/{page}/{v}"));
        r
    }
}

#[async_trait]
impl Enricher for UrlHaus {
    fn name(&self) -> &str {
        Self::NAME
    }
    fn kinds(&self) -> &[IndicatorKind] {
        Self::KINDS
    }
    fn default_rate(&self) -> RateLimit {
        Self::rate()
    }
    fn configured(&self) -> bool {
        self.key.is_some()
    }

    async fn lookup(&self, ind: &PublicIndicator, http: &dyn Http) -> EnrichmentResult {
        let Some(key) = &self.key else {
            return EnrichmentResult::status(Self::NAME, TiStatus::SkippedNoKey, "no key");
        };
        let v = ind.value();
        let (endpoint, field) = match ind.kind() {
            IndicatorKind::Url => ("url", "url"),
            IndicatorKind::Domain | IndicatorKind::Ip => ("host", "host"),
            IndicatorKind::Hash if v.len() == 64 => ("payload", "sha256_hash"),
            IndicatorKind::Hash if v.len() == 32 => ("payload", "md5_hash"),
            IndicatorKind::Hash => {
                return EnrichmentResult::status(
                    Self::NAME,
                    TiStatus::Error,
                    "only MD5 and SHA-256 are supported",
                );
            }
        };
        let req = EgressRequest::post_form(
            format!("https://urlhaus-api.abuse.ch/v1/{endpoint}/"),
            &[(field, v)],
        )
        .header("auth-key", key.expose());
        let (_, body) = match fetch(Self::NAME, http, req).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        match body["query_status"].as_str() {
            Some("ok") => {
                let mut r = ok(Self::NAME);
                let fact = match endpoint {
                    "url" => format!(
                        "listed by URLhaus (status {}, threat {})",
                        body["url_status"].as_str().unwrap_or("?"),
                        body["threat"].as_str().unwrap_or("?")
                    ),
                    "host" => format!("host has {} URLhaus URL(s)", text(&body["url_count"])),
                    _ => format!(
                        "known payload ({})",
                        body["signature"].as_str().unwrap_or("no signature")
                    ),
                };
                verdict(&mut r, TiVerdict::Malicious, fact);
                r.link = body["urlhaus_reference"].as_str().map(str::to_string);
                r
            }
            Some("no_results") => {
                EnrichmentResult::status(Self::NAME, TiStatus::NotFound, "not in URLhaus")
            }
            other => EnrichmentResult::status(
                Self::NAME,
                TiStatus::Error,
                format!("query_status {}", other.unwrap_or("missing")),
            ),
        }
    }
}

#[async_trait]
impl Enricher for ThreatFox {
    fn name(&self) -> &str {
        Self::NAME
    }
    fn kinds(&self) -> &[IndicatorKind] {
        Self::KINDS
    }
    fn default_rate(&self) -> RateLimit {
        Self::rate()
    }
    fn configured(&self) -> bool {
        self.key.is_some()
    }

    async fn lookup(&self, ind: &PublicIndicator, http: &dyn Http) -> EnrichmentResult {
        let Some(key) = &self.key else {
            return EnrichmentResult::status(Self::NAME, TiStatus::SkippedNoKey, "no key");
        };
        let v = ind.value();
        let body = match ind.kind() {
            IndicatorKind::Hash => json!({ "query": "search_hash", "hash": v }),
            // ThreatFox stores IPs as ip:port, so IPs need the non-exact search.
            IndicatorKind::Ip => {
                json!({ "query": "search_ioc", "search_term": v, "exact_match": false })
            }
            _ => json!({ "query": "search_ioc", "search_term": v, "exact_match": true }),
        };
        let req = EgressRequest::post_json("https://threatfox-api.abuse.ch/api/v1/", &body)
            .header("auth-key", key.expose());
        let (_, body) = match fetch(Self::NAME, http, req).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        match body["query_status"].as_str() {
            Some("ok") => {
                let first = &body["data"][0];
                let mut r = ok(Self::NAME);
                let fact = format!(
                    "{} ({}), confidence {}%",
                    first["malware_printable"]
                        .as_str()
                        .unwrap_or("unknown malware"),
                    first["threat_type"].as_str().unwrap_or("?"),
                    first["confidence_level"].as_u64().unwrap_or(0)
                );
                verdict(&mut r, TiVerdict::Malicious, fact);
                let id = text(&first["id"]);
                r.link = (id != "?").then(|| format!("https://threatfox.abuse.ch/ioc/{id}/"));
                r
            }
            Some("no_result") | Some("no_results") => {
                EnrichmentResult::status(Self::NAME, TiStatus::NotFound, "not in ThreatFox")
            }
            other => EnrichmentResult::status(
                Self::NAME,
                TiStatus::Error,
                format!("query_status {}", other.unwrap_or("missing")),
            ),
        }
    }
}

#[async_trait]
impl Enricher for GreyNoise {
    fn name(&self) -> &str {
        Self::NAME
    }
    fn kinds(&self) -> &[IndicatorKind] {
        Self::KINDS
    }
    fn default_rate(&self) -> RateLimit {
        Self::rate()
    }
    fn configured(&self) -> bool {
        self.key.is_some()
    }

    async fn lookup(&self, ind: &PublicIndicator, http: &dyn Http) -> EnrichmentResult {
        let Some(key) = &self.key else {
            return EnrichmentResult::status(Self::NAME, TiStatus::SkippedNoKey, "no key");
        };
        let v = ind.value();
        if !path_safe(v) {
            return EnrichmentResult::status(Self::NAME, TiStatus::Error, "unsupported characters");
        }
        let req = EgressRequest::get(format!("https://api.greynoise.io/v3/community/{v}"))
            .header("key", key.expose());
        let (status, body) = match fetch(Self::NAME, http, req).await {
            Ok(x) => x,
            Err(r) => return r,
        };
        if status == 404 {
            return EnrichmentResult::status(
                Self::NAME,
                TiStatus::NotFound,
                "not observed by GreyNoise",
            );
        }
        let class = body["classification"].as_str().unwrap_or("unknown");
        let mut r = ok(Self::NAME);
        let v_ = match class {
            "malicious" => TiVerdict::Malicious,
            "benign" => TiVerdict::Clean,
            _ => TiVerdict::Unknown,
        };
        let mut fact = format!("classification {class}");
        if let Some(n) = body["name"].as_str().filter(|n| *n != "unknown") {
            fact.push_str(&format!(", {n}"));
        }
        if body["riot"].as_bool() == Some(true) {
            fact.push_str(", common business service");
        }
        verdict(&mut r, v_, fact);
        r.link = body["link"].as_str().map(str::to_string);
        r
    }
}

/// Runs the configured providers with per-provider pacing, a per-run cap and the cache.
pub struct TiRunner {
    enrichers: Vec<Box<dyn Enricher>>,
    cache: Option<Cache>,
}

impl TiRunner {
    pub fn new(enrichers: Vec<Box<dyn Enricher>>) -> Self {
        Self {
            enrichers,
            cache: None,
        }
    }

    /// Keys from SUDARE_VIRUSTOTAL_KEY, SUDARE_ABUSEIPDB_KEY, SUDARE_OTX_KEY,
    /// SUDARE_ABUSECH_KEY (URLhaus + ThreatFox) and SUDARE_GREYNOISE_KEY.
    pub fn from_env() -> Self {
        Self::with_keys(|key_name| {
            ApiKey::from_env(&format!("SUDARE_{}_KEY", key_name.to_ascii_uppercase()))
        })
    }

    /// Key names: `virustotal`, `abuseipdb`, `otx`, `abusech` (URLhaus + ThreatFox),
    /// `greynoise`.
    pub fn with_keys(key: impl Fn(&str) -> Option<ApiKey>) -> Self {
        Self::new(vec![
            Box::new(VirusTotal::new(key("virustotal"))),
            Box::new(AbuseIpDb::new(key("abuseipdb"))),
            Box::new(Otx::new(key("otx"))),
            Box::new(UrlHaus::new(key("abusech"))),
            Box::new(ThreatFox::new(key("abusech"))),
            Box::new(GreyNoise::new(key("greynoise"))),
        ])
    }

    pub fn with_cache(mut self, cache: Cache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn configured(&self) -> Vec<&str> {
        self.enrichers
            .iter()
            .filter(|e| e.configured())
            .map(|e| e.name())
            .collect()
    }

    /// One result list per indicator, in the same order.
    pub async fn enrich(
        &self,
        indicators: &[PublicIndicator],
        http: &dyn Http,
    ) -> Vec<Vec<EnrichmentResult>> {
        let mut out = vec![Vec::new(); indicators.len()];
        for e in self.enrichers.iter().filter(|e| e.configured()) {
            let rate = e.default_rate();
            let interval = Duration::from_secs_f64(60.0 / f64::from(rate.per_minute.max(1)));
            let mut last: Option<Instant> = None;
            let mut done = 0;
            for (i, ind) in indicators.iter().enumerate() {
                if !e.kinds().contains(&ind.kind()) {
                    continue;
                }
                if let Some(hit) = self.cache.as_ref().and_then(|c| c.get(e.name(), ind)) {
                    out[i].push(hit);
                    continue;
                }
                if done >= rate.per_run {
                    out[i].push(EnrichmentResult::status(
                        e.name(),
                        TiStatus::SkippedQuota,
                        "per-analysis lookup limit reached",
                    ));
                    continue;
                }
                if let Some(t) = last {
                    tokio::time::sleep(interval.saturating_sub(t.elapsed())).await;
                }
                last = Some(Instant::now());
                done += 1;
                let r = e.lookup(ind, http).await;
                if matches!(r.status, TiStatus::Ok | TiStatus::NotFound)
                    && let Some(c) = &self.cache
                {
                    c.put(e.name(), ind, &r);
                }
                out[i].push(r);
            }
        }
        out
    }
}

/// Key names accepted by [`TiRunner::with_keys`].
pub const TI_KEY_NAMES: &[&str] = &["virustotal", "abuseipdb", "otx", "abusech", "greynoise"];
