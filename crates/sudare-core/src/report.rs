//! Output schema, validation, unmasking and rendering.

use crate::attack::{self, Lookup};
use crate::mask::{MaskMap, MaskStats, MaskedInput};
use crate::policy::{Action, Mode};
use crate::prompt::Sampling;
use crate::types::{EntityType, Scope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

pub const SCHEMA_VERSION: u32 = 1;

/// What the model must return.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelAnalysis {
    /// 2-4 sentences: what happened, to which assets, and how sure you are.
    pub summary: String,
    pub verdict: Verdict,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Key events in time order.
    #[serde(default)]
    pub timeline: Vec<TimelineItem>,
    /// Identifiers that matter, as placeholders or values exactly as they appear in the logs.
    #[serde(default)]
    pub entities: Vec<EntityNote>,
    #[serde(default)]
    pub attack_techniques: Vec<Technique>,
    pub recommended_actions: RecommendedActions,
    #[serde(default)]
    pub open_questions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    TruePositive,
    LikelyTruePositive,
    Benign,
    FalsePositive,
    InsufficientData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Severity {
    pub level: SeverityLevel,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Confidence {
    /// 0 to 1.
    pub score: f64,
    /// Evidence that would raise or lower the score.
    pub would_change_it: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimelineItem {
    pub timestamp: Option<String>,
    pub description: String,
    /// Line numbers from the L0042| references.
    #[serde(default)]
    pub source_lines: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityNote {
    #[serde(rename = "ref")]
    pub reference: String,
    pub role: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Technique {
    /// T#### or T####.###
    pub id: String,
    pub name: String,
    pub evidence: String,
    #[serde(default)]
    pub evidence_lines: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecommendedActions {
    #[serde(default)]
    pub containment: Vec<String>,
    #[serde(default)]
    pub investigation: Vec<Query>,
    #[serde(default)]
    pub eradication: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub language: String,
    pub query: String,
    pub purpose: String,
}

/// JSON Schema for [`ModelAnalysis`], given to providers that support structured output.
pub fn model_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(ModelAnalysis)).expect("schema serializes")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TiStatus {
    Ok,
    NotFound,
    SkippedNoKey,
    SkippedQuota,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TiVerdict {
    Malicious,
    Suspicious,
    Clean,
    Unknown,
}

/// One provider's answer for one public indicator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrichmentResult {
    pub provider: String,
    pub status: TiStatus,
    pub verdict: Option<TiVerdict>,
    pub score: Option<f64>,
    pub facts: Vec<String>,
    pub link: Option<String>,
    #[serde(default)]
    pub cached: bool,
}

impl EnrichmentResult {
    pub fn status(provider: &str, status: TiStatus, fact: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            status,
            verdict: None,
            score: None,
            facts: vec![fact.into()],
            link: None,
            cached: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub analysis: Option<ModelAnalysis>,
    /// Set when the model never produced valid JSON.
    pub raw_output: Option<String>,
    /// Entities found by the tool (not the model), with threat-intel results.
    pub entities: Vec<ReportEntity>,
    pub warnings: Vec<Warning>,
    pub meta: Meta,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportEntity {
    pub value: String,
    pub kind: EntityType,
    pub scope: Scope,
    pub action: Action,
    pub token: Option<String>,
    pub enrichment: Vec<EnrichmentResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Warning {
    pub code: String,
    pub detail: String,
}

impl Warning {
    pub fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Meta {
    pub provider: String,
    pub model: String,
    pub mode: Mode,
    pub parser: String,
    pub lines: u32,
    pub events: usize,
    pub parse_errors: usize,
    pub mask: MaskStats,
    pub sampling: Sampling,
    pub attack_version: String,
    pub created_at: String,
}

/// Pull the JSON object out of a reply (tolerates code fences and chatter around it).
pub fn parse_model_output(raw: &str) -> Result<ModelAnalysis, String> {
    let (Some(start), Some(end)) = (raw.find('{'), raw.rfind('}')) else {
        return Err("no JSON object in the reply".into());
    };
    if end < start {
        return Err("no JSON object in the reply".into());
    }
    serde_json::from_str(&raw[start..=end]).map_err(|e| e.to_string())
}

/// Post-checks on a structurally valid analysis. Mutates it and returns warnings.
pub fn validate(a: &mut ModelAnalysis, input: &MaskedInput, map: &MaskMap) -> Vec<Warning> {
    let mut w = Vec::new();
    let max = input.line_count();
    let check = |lines: &mut Vec<u32>, ctx: &str, w: &mut Vec<Warning>| {
        let before = lines.len();
        lines.retain(|l| (1..=max).contains(l));
        if lines.len() != before {
            w.push(Warning::new(
                "line_ref_out_of_range",
                format!(
                    "{ctx}: dropped {} reference(s) outside lines 1-{max}",
                    before - lines.len()
                ),
            ));
        }
        lines.sort_unstable();
        lines.dedup();
    };
    for t in &mut a.timeline {
        check(&mut t.source_lines, "timeline", &mut w);
    }

    let score = a.confidence.score;
    if !(0.0..=1.0).contains(&score) {
        a.confidence.score = if score.is_nan() {
            0.0
        } else {
            score.clamp(0.0, 1.0)
        };
        w.push(Warning::new(
            "confidence_clamped",
            format!("confidence {score} clamped to {}", a.confidence.score),
        ));
    }

    let idx = attack::index();
    let mut kept: Vec<Technique> = Vec::new();
    for mut t in std::mem::take(&mut a.attack_techniques) {
        check(
            &mut t.evidence_lines,
            &format!("technique {}", t.id),
            &mut w,
        );
        let id = t.id.trim().to_ascii_uppercase();
        match idx.lookup(&id) {
            Lookup::Current(name) => {
                t.id = id;
                t.name = name;
            }
            Lookup::Revoked { successor, name } => {
                w.push(Warning::new(
                    "technique_revoked",
                    format!(
                        "{id} is revoked in ATT&CK {}; replaced by {successor}",
                        idx.version()
                    ),
                ));
                t.id = successor;
                t.name = name;
            }
            Lookup::Deprecated(name) => {
                w.push(Warning::new(
                    "technique_deprecated",
                    format!("{id} is deprecated in ATT&CK {}", idx.version()),
                ));
                t.id = id;
                t.name = name;
            }
            Lookup::Unknown => {
                w.push(Warning::new(
                    "unknown_technique",
                    format!("{id:?} is not in ATT&CK {}; dropped", idx.version()),
                ));
                continue;
            }
        }
        if !kept.iter().any(|k| k.id == t.id) {
            kept.push(t);
        }
    }
    a.attack_techniques = kept;

    let text = input.text().to_lowercase();
    // CEF, LEEF and JSON escape backslashes; models quote paths unescaped.
    let unescaped = text.replace("\\\\", "\\");
    let seen = |r: &str| {
        let r = r.to_lowercase();
        !r.is_empty() && (text.contains(&r) || unescaped.contains(&r))
    };
    a.entities.retain(|e| {
        let r = e.reference.trim();
        let ok = if r.contains('[')
            || r.contains('_') && r.chars().any(|c| c.is_ascii_digit()) && r.to_uppercase() == r
        {
            map.canonical_token(r).is_some() || seen(r)
        } else {
            seen(r)
        };
        if !ok {
            w.push(Warning::new(
                "unverified_entity",
                format!("{r:?} does not appear in the input; dropped"),
            ));
        }
        ok
    });
    w
}

fn walk_strings(v: &mut serde_json::Value, f: &mut impl FnMut(&mut String)) {
    match v {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| walk_strings(x, f)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| walk_strings(x, f)),
        _ => {}
    }
}

/// Restore real values in every string of the analysis. Returns unknown tokens seen.
pub fn unmask_analysis(a: &ModelAnalysis, map: &MaskMap) -> (ModelAnalysis, Vec<String>) {
    let mut v = serde_json::to_value(a).expect("analysis serializes");
    let mut unknown = Vec::new();
    walk_strings(&mut v, &mut |s| {
        let u = map.unmask(s);
        *s = u.text;
        unknown.extend(u.unknown);
    });
    (
        serde_json::from_value(v).unwrap_or_else(|_| a.clone()),
        unknown,
    )
}

/// RFC 3339 UTC timestamp from Unix seconds (no clock access here; callers pass it in).
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Neutralise model text for markdown: no raw HTML, no clickable links.
fn md(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace("](", "]\\(")
        .replace('|', "\\|")
        .replace('\n', " ")
}

fn fence(code: &str) -> String {
    let longest = code.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    "`".repeat(longest.max(2) + 1)
}

fn label<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.replace('_', " ")))
        .unwrap_or_default()
}

pub fn render_markdown(r: &Report) -> String {
    let mut s = String::from("# Incident analysis\n\n");
    match &r.analysis {
        Some(a) => {
            let _ = writeln!(
                s,
                "**Verdict:** {} · **Severity:** {} · **Confidence:** {:.2}\n\n{}\n",
                label(&a.verdict),
                label(&a.severity.level),
                a.confidence.score,
                md(&a.summary)
            );
            let _ = writeln!(s, "## Severity\n\n{}\n", md(&a.severity.rationale));
            let _ = writeln!(
                s,
                "**What would change the confidence:** {}\n",
                md(&a.confidence.would_change_it)
            );
            if !a.timeline.is_empty() {
                s.push_str("## Timeline\n\n| Time | Event | Lines |\n|---|---|---|\n");
                for t in &a.timeline {
                    let lines = t
                        .source_lines
                        .iter()
                        .map(|l| format!("L{l}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = writeln!(
                        s,
                        "| {} | {} | {} |",
                        md(t.timestamp.as_deref().unwrap_or("")),
                        md(&t.description),
                        lines
                    );
                }
                s.push('\n');
            }
            if !a.entities.is_empty() {
                s.push_str("## Entities\n\n| Entity | Role | Note |\n|---|---|---|\n");
                for e in &a.entities {
                    let _ = writeln!(
                        s,
                        "| `{}` | {} | {} |",
                        md(&e.reference).replace('`', "'"),
                        md(&e.role),
                        md(&e.note)
                    );
                }
                s.push('\n');
            }
            if !a.attack_techniques.is_empty() {
                s.push_str("## ATT&CK techniques\n\n");
                for t in &a.attack_techniques {
                    let lines = t
                        .evidence_lines
                        .iter()
                        .map(|l| format!("L{l}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = writeln!(
                        s,
                        "- **{}** {}: {} ({})",
                        md(&t.id),
                        md(&t.name),
                        md(&t.evidence),
                        lines
                    );
                }
                s.push('\n');
            }
            let ra = &a.recommended_actions;
            s.push_str("## Recommended actions\n\n");
            for (title, items) in [
                ("Containment", &ra.containment),
                ("Eradication", &ra.eradication),
            ] {
                if !items.is_empty() {
                    let _ = writeln!(s, "### {title}\n");
                    for i in items {
                        let _ = writeln!(s, "- {}", md(i));
                    }
                    s.push('\n');
                }
            }
            if !ra.investigation.is_empty() {
                s.push_str("### Investigation\n\n");
                for q in &ra.investigation {
                    let f = fence(&q.query);
                    let lang: String = q
                        .language
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric())
                        .collect();
                    let _ = writeln!(
                        s,
                        "{}\n\n{f}{}\n{}\n{f}\n",
                        md(&q.purpose),
                        lang.to_lowercase(),
                        q.query
                    );
                }
            }
            if !a.open_questions.is_empty() {
                s.push_str("## Open questions\n\n");
                for q in &a.open_questions {
                    let _ = writeln!(s, "- {}", md(q));
                }
                s.push('\n');
            }
        }
        None => {
            s.push_str("**The model did not return a valid analysis.** Its raw reply follows, unmasked.\n\n");
            let raw = r.raw_output.as_deref().unwrap_or("");
            let f = fence(raw);
            let _ = writeln!(s, "{f}text\n{raw}\n{f}\n");
        }
    }

    let checked: Vec<&ReportEntity> = r
        .entities
        .iter()
        .filter(|e| !e.enrichment.is_empty())
        .collect();
    if !checked.is_empty() {
        s.push_str("## Threat intel\n\n| Indicator | Provider | Result |\n|---|---|---|\n");
        for e in checked {
            for x in &e.enrichment {
                let result = match (&x.verdict, x.status) {
                    (Some(v), _) => label(v),
                    (None, st) => label(&st),
                };
                let detail = x.facts.join("; ");
                let _ = writeln!(
                    s,
                    "| `{}` | {} | {} {} |",
                    md(&e.value).replace('`', "'"),
                    md(&x.provider),
                    result,
                    md(&detail)
                );
            }
        }
        s.push('\n');
    }
    if !r.warnings.is_empty() {
        s.push_str("## Warnings\n\n");
        for w in &r.warnings {
            let _ = writeln!(s, "- `{}` {}", w.code, md(&w.detail));
        }
        s.push('\n');
    }
    let m = &r.meta;
    let masked: usize = m.mask.masked.values().sum();
    let _ = writeln!(
        s,
        "---\n{} / {} · mode {} · parser {} · {} lines, {} events · {masked} values masked · ATT&CK {} · {}\n\nATT&CK® data © The MITRE Corporation.",
        md(&m.provider),
        md(&m.model),
        label(&m.mode),
        md(&m.parser),
        m.lines,
        m.events,
        m.attack_version,
        m.created_at
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_793_232_000), "2026-10-29T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn extracts_json_from_chatter() {
        let raw = r#"Sure! ```json
{"summary":"s","verdict":"benign","severity":{"level":"low","rationale":"r"},"confidence":{"score":0.5,"would_change_it":"x"},"recommended_actions":{}}
```"#;
        assert_eq!(parse_model_output(raw).unwrap().verdict, Verdict::Benign);
        assert!(parse_model_output(r#"{"summary":"s","extra":1}"#).is_err());
    }

    #[test]
    fn markdown_escapes_html_and_links() {
        assert_eq!(
            md("<script>x</script> https://a.example.org"),
            "&lt;script&gt;x&lt;/script&gt; hxxps://a.example.org"
        );
        assert_eq!(fence("a ``` b"), "````");
    }

    #[test]
    fn entity_check_accepts_unescaped_backslashes() {
        let engine = crate::Engine::new(crate::Policy::default()).unwrap();
        let p = engine
            .prepare(
                r"CEF:0|V|P|1|1|x|5|fname=C:\\Users\\Public\\invoice.pdf.exe",
                None,
                [7; 32],
            )
            .unwrap();
        let raw = r#"{"summary":"s","verdict":"benign","severity":{"level":"low","rationale":"r"},"confidence":{"score":0.5,"would_change_it":"x"},"recommended_actions":{},"entities":[{"ref":"C:\\Users\\Public\\invoice.pdf.exe","role":"file"},{"ref":"C:\\nope.exe","role":"file"}]}"#;
        let mut a = parse_model_output(raw).unwrap();
        let w = validate(&mut a, &p.input, &p.map);
        assert_eq!(a.entities.len(), 1, "{w:?}");
        assert_eq!(w.len(), 1);
    }
}
