//! Release-blocking leak test. Every fixture × every LLM adapter × both modes, with
//! every outgoing request recorded by a fake `Http`. Ground truth is
//! fixtures/manifest.json, not the extractors' own output, and requests are checked
//! both raw and decoded (JSON strings, URL and form encoding).
//!
//! No real network: the only `Http` used here is `Recorder`.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use sudare_core::{Engine, Policy};
use sudare_egress::http::{EgressRequest, EgressResponse, Http, HttpError};
use sudare_egress::llm::{self, ApiKey, ProviderConfig, ProviderKind};
use sudare_egress::pipeline::{self, AnalyzeOptions};
use sudare_egress::ti::{
    AbuseIpDb, Enricher, GreyNoise, Otx, ThreatFox, TiRunner, UrlHaus, VirusTotal,
};

#[derive(Deserialize)]
struct Manifest {
    files: BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
struct Entry {
    sensitive: Vec<String>,
    public: Vec<String>,
}

const KEY_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-goog-api-key",
    "x-apikey",
    "key",
    "x-otx-api-key",
    "auth-key",
];
const TI_HOSTS: &[&str] = &[
    "virustotal.com",
    "abuseipdb.com",
    "alienvault.com",
    "abuse.ch",
    "greynoise.io",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

/// First real token in the logs block of a request (not a literal or a redaction).
fn first_token(body: &str) -> Option<String> {
    let mut rest = &body[body.find("<<<LOGS")?..];
    while let Some(i) = rest.find("[[") {
        let tail = &rest[i..];
        let end = tail.find("]]")?;
        let token = &tail[..end + 2];
        if !token.contains("LITERAL")
            && !token.contains("REDACTED")
            && !token.contains(' ')
            && token.len() < 40
        {
            return Some(token.to_string());
        }
        rest = &tail[2..];
    }
    None
}

fn canned_analysis(token: &str) -> String {
    json!({
        "summary": format!("Repeated failures against {token} followed by a success."),
        "verdict": "likely_true_positive",
        "severity": { "level": "high", "rationale": "credential attack" },
        "confidence": { "score": 0.8, "would_change_it": "MFA logs" },
        "timeline": [{ "timestamp": null, "description": format!("{token} targeted"), "source_lines": [1, 999] }],
        "entities": [
            { "ref": token, "role": "target", "note": "" },
            { "ref": "[[HOST_424242]]", "role": "invented by the model", "note": "" }
        ],
        "attack_techniques": [
            { "id": "T1110", "name": "x", "evidence": "failed logons", "evidence_lines": [1] },
            { "id": "T1002", "name": "old", "evidence": "e", "evidence_lines": [1] },
            { "id": "T9999", "name": "fake", "evidence": "e", "evidence_lines": [1] }
        ],
        "recommended_actions": {
            "containment": ["Disable the account"],
            "investigation": [{ "language": "kql", "query": "SigninLogs | take 10", "purpose": "check" }],
            "eradication": []
        },
        "open_questions": []
    })
    .to_string()
}

#[derive(Default)]
struct Recorder {
    log: Mutex<Vec<EgressRequest>>,
}

#[async_trait]
impl Http for Recorder {
    async fn send(&self, req: EgressRequest) -> Result<EgressResponse, HttpError> {
        let body = String::from_utf8_lossy(req.body.as_deref().unwrap_or(&[])).into_owned();
        let url = req.url.clone();
        self.log.lock().unwrap().push(req);
        let analysis = canned_analysis(&first_token(&body).unwrap_or_else(|| "nothing".into()));
        let (status, v) = if url.contains("/api/chat") {
            (
                200,
                json!({ "model": "test", "message": { "content": analysis } }),
            )
        } else if url.contains("chat/completions") {
            (
                200,
                json!({ "model": "test", "choices": [{ "message": { "content": analysis } }] }),
            )
        } else if url.contains("/v1/messages") {
            (
                200,
                json!({ "model": "test", "content": [{ "type": "text", "text": analysis }] }),
            )
        } else if url.contains(":generateContent") {
            (
                200,
                json!({ "candidates": [{ "content": { "parts": [{ "text": analysis }] } }] }),
            )
        } else if url.contains("virustotal.com") {
            (
                200,
                json!({ "data": { "attributes": { "last_analysis_stats": { "malicious": 3, "suspicious": 1, "harmless": 50, "undetected": 10 } } } }),
            )
        } else if url.contains("abuseipdb.com") {
            (
                200,
                json!({ "data": { "abuseConfidenceScore": 90, "totalReports": 12, "isp": "Example ISP" } }),
            )
        } else {
            (404, json!({}))
        };
        Ok(EgressResponse {
            status,
            headers: Vec::new(),
            body: serde_json::to_vec(&v).unwrap(),
        })
    }
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(s.replace('+', "%2B").as_bytes())
        .map(|(k, v)| {
            if v.is_empty() {
                k.into_owned()
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn strings(v: &Value, out: &mut String) {
    match v {
        Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| {
            out.push_str(k);
            out.push('\n');
            strings(x, out);
        }),
        _ => {}
    }
}

/// Everything a request exposes, raw and decoded, lowercased. Key headers excluded.
fn exposed(r: &EgressRequest) -> String {
    let mut s = format!("{}\n{}\n", r.url, percent_decode(&r.url));
    for (k, v) in &r.headers {
        if !KEY_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
            s.push_str(v);
            s.push('\n');
        }
    }
    let body = String::from_utf8_lossy(r.body.as_deref().unwrap_or(&[])).into_owned();
    s.push_str(&body);
    s.push('\n');
    if let Ok(v) = serde_json::from_str::<Value>(&body) {
        strings(&v, &mut s);
    }
    s.push_str(&percent_decode(&body));
    s.to_lowercase()
}

fn runner() -> TiRunner {
    let k = || ApiKey::new("test-key".into());
    let all: Vec<Box<dyn Enricher>> = vec![
        Box::new(VirusTotal::new(k())),
        Box::new(AbuseIpDb::new(k())),
        Box::new(Otx::new(k())),
        Box::new(UrlHaus::new(k())),
        Box::new(ThreatFox::new(k())),
        Box::new(GreyNoise::new(k())),
    ];
    TiRunner::new(all)
}

fn provider(kind: ProviderKind) -> Box<dyn llm::LlmProvider> {
    let mut cfg = ProviderConfig::new(kind);
    cfg.api_key = ApiKey::new("test-key".into());
    if kind == ProviderKind::OpenAiCompatible {
        cfg.base_url = Some("https://llm.example.com/v1".into());
        cfg.model = Some("test-model".into());
    }
    llm::build(cfg).unwrap()
}

#[tokio::test(start_paused = true)]
async fn no_sensitive_value_leaves_through_any_adapter() {
    let manifest: Manifest =
        serde_json::from_str(&std::fs::read_to_string(root().join("manifest.json")).unwrap())
            .unwrap();
    let kinds = [
        ProviderKind::Ollama,
        ProviderKind::OpenAi,
        ProviderKind::Anthropic,
        ProviderKind::Gemini,
        ProviderKind::OpenAiCompatible,
    ];
    let mut runs = 0;
    for strict in [false, true] {
        let mut policy = Policy::load(&root().join("policy.toml")).unwrap();
        if strict {
            policy = policy.strict();
        }
        let engine = Engine::new(policy).unwrap().documentation_ranges_public();
        for (name, entry) in &manifest.files {
            let text =
                String::from_utf8_lossy(&std::fs::read(root().join(name)).unwrap()).into_owned();
            for kind in kinds {
                let ctx = format!("{name} / {kind:?} / strict={strict}");
                let http = Recorder::default();
                let mut prepared = engine.prepare(&text, None, [5; 32]).unwrap();
                let enrichment = pipeline::enrich(&prepared, &runner(), &http).await;
                let p = provider(kind);
                let opts = AnalyzeOptions {
                    rule: Some(("Brute force".into(), "failures > 3".into())),
                    max_input_chars: None,
                    now_unix: 0,
                };
                let result = pipeline::analyze(
                    &engine,
                    &mut prepared,
                    &enrichment,
                    p.as_ref(),
                    &http,
                    &opts,
                )
                .await
                .unwrap_or_else(|e| panic!("{ctx}: {e}"));

                let log = http.log.lock().unwrap();
                let (ti, llm): (Vec<&EgressRequest>, Vec<&EgressRequest>) = log
                    .iter()
                    .partition(|r| TI_HOSTS.iter().any(|h| r.url.contains(h)));
                assert!(!llm.is_empty(), "{ctx}: no LLM request");
                for r in log.iter() {
                    let seen = exposed(r);
                    for s in &entry.sensitive {
                        assert!(
                            !seen.contains(&s.to_lowercase()),
                            "{ctx}: sensitive {s:?} sent in {r:?}"
                        );
                    }
                }
                if strict {
                    for r in &llm {
                        let seen = exposed(r);
                        for s in &entry.public {
                            assert!(
                                !seen.contains(&s.to_lowercase()),
                                "{ctx}: public {s:?} sent to the LLM in strict mode"
                            );
                        }
                    }
                }
                if !name.starts_with("malformed/") && !entry.public.is_empty() {
                    assert!(
                        !ti.is_empty(),
                        "{ctx}: public indicators were never looked up"
                    );
                }

                // The model's placeholders came back as real values.
                let report = &result.report;
                let a = report
                    .analysis
                    .as_ref()
                    .unwrap_or_else(|| panic!("{ctx}: no analysis"));
                assert!(
                    !a.summary.contains("[["),
                    "{ctx}: summary not unmasked: {}",
                    a.summary
                );
                let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
                for code in [
                    "unknown_technique",
                    "technique_revoked",
                    "line_ref_out_of_range",
                    "unverified_entity",
                ] {
                    assert!(
                        codes.contains(&code),
                        "{ctx}: missing warning {code}: {codes:?}"
                    );
                }
                assert!(
                    a.attack_techniques.iter().any(|t| t.id == "T1560"),
                    "{ctx}: revoked T1002 not replaced"
                );
                assert!(!a.attack_techniques.iter().any(|t| t.id == "T9999"));
                runs += 1;
            }
        }
    }
    assert_eq!(runs, 2 * 5 * manifest.files.len());
}

/// Negative control: with usernames set to "keep", the detector must see the leak.
#[tokio::test]
async fn the_detector_catches_a_deliberate_leak() {
    let policy = Policy::from_toml("[actions]\nusername = \"keep\"").unwrap();
    let engine = Engine::new(policy).unwrap();
    let text = std::fs::read_to_string(root().join("syslog3164.log")).unwrap();
    let mut prepared = engine.prepare(&text, None, [5; 32]).unwrap();
    let http = Recorder::default();
    let opts = AnalyzeOptions {
        rule: None,
        max_input_chars: None,
        now_unix: 0,
    };
    let p = provider(ProviderKind::Ollama);
    pipeline::analyze(&engine, &mut prepared, &[], p.as_ref(), &http, &opts)
        .await
        .unwrap();
    let log = http.log.lock().unwrap();
    assert!(log.iter().any(|r| exposed(r).contains("jdoe")));
}

#[tokio::test]
async fn provider_requests_have_the_expected_shape() {
    let engine = Engine::new(Policy::default()).unwrap();
    let mut prepared = engine
        .prepare("user=jdoe host=fw01 failed login", None, [1; 32])
        .unwrap();
    for kind in [
        ProviderKind::Ollama,
        ProviderKind::OpenAi,
        ProviderKind::Anthropic,
        ProviderKind::Gemini,
    ] {
        let http = Recorder::default();
        let p = provider(kind);
        let opts = AnalyzeOptions {
            rule: None,
            max_input_chars: None,
            now_unix: 0,
        };
        pipeline::analyze(&engine, &mut prepared, &[], p.as_ref(), &http, &opts)
            .await
            .unwrap();
        let log = http.log.lock().unwrap();
        let r = &log[0];
        let body: Value = serde_json::from_slice(r.body.as_deref().unwrap()).unwrap();
        match kind {
            ProviderKind::Ollama => {
                assert!(p.is_local());
                assert_eq!(body["options"]["num_ctx"], 16_384);
                assert!(body["format"].is_object());
            }
            ProviderKind::OpenAi => {
                assert!(!p.is_local());
                assert_eq!(body["response_format"]["type"], "json_schema");
                assert!(
                    r.headers
                        .iter()
                        .any(|(k, v)| k == "authorization" && v == "Bearer test-key")
                );
            }
            ProviderKind::Anthropic => {
                assert!(body["system"].as_str().unwrap().contains("untrusted data"));
                assert_eq!(body["messages"][0]["role"], "user");
            }
            ProviderKind::Gemini => {
                assert!(!r.url.contains("key="), "Gemini key must not be in the URL");
                assert!(r.headers.iter().any(|(k, _)| k == "x-goog-api-key"));
            }
            ProviderKind::OpenAiCompatible => {}
        }
    }
}

#[tokio::test]
async fn chat_reuses_the_map_and_masks_questions() {
    let engine = Engine::new(Policy::default()).unwrap();
    let mut prepared = engine
        .prepare(
            "user=jdoe host=fw01 failed login from 10.1.2.3",
            None,
            [2; 32],
        )
        .unwrap();
    let http = Recorder::default();
    let p = provider(ProviderKind::Ollama);
    let mut history = Vec::new();
    let answer = pipeline::chat(
        &engine,
        &mut prepared,
        "{}",
        &mut history,
        "did jdoe log in to fw01 or ws-99.corp.local?",
        p.as_ref(),
        &http,
        None,
    )
    .await
    .unwrap();
    let log = http.log.lock().unwrap();
    let seen = exposed(&log[0]);
    for v in ["jdoe", "fw01", "10.1.2.3", "ws-99.corp.local"] {
        assert!(!seen.contains(v), "{v} leaked in chat");
    }
    assert!(!answer.contains("[[USER_"), "answer not unmasked: {answer}");
    assert_eq!(history.len(), 1);
}
