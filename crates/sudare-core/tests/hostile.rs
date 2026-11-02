//! Hostile input: prompt injection in a user-agent, XSS in a URL, look-alike Unicode,
//! token injection and regex denial of service.

use std::path::PathBuf;
use std::time::{Duration, Instant};
use sudare_core::prompt::{self, PromptInputs, Sampling};
use sudare_core::report::{self, Meta, Report};
use sudare_core::{Engine, EntityType, MaskStats, Mode, Policy, Role};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn engine() -> Engine {
    Engine::new(Policy::load(&root().join("policy.toml")).unwrap())
        .unwrap()
        .documentation_ranges_public()
}

fn hostile() -> String {
    std::fs::read_to_string(root().join("hostile.log")).unwrap()
}

#[test]
fn injected_text_stays_inside_the_data_block() {
    let p = engine().prepare(&hostile(), None, [3; 32]).unwrap();
    let inputs = PromptInputs {
        max_input_chars: 100_000,
        rule: None,
        threat_intel: None,
    };
    let (prompt, _) = prompt::analysis(&p.input, &p.map, "{}", &inputs);
    let user = prompt
        .messages()
        .iter()
        .find(|m| m.role() == Role::User)
        .unwrap()
        .content();
    let system = prompt.system().unwrap();

    // The real delimiter carries a per-analysis nonce the attacker cannot know.
    let end = user
        .lines()
        .rfind(|l| l.starts_with("<<<END LOGS "))
        .unwrap();
    assert_ne!(end, "<<<END LOGS 0000>>>");
    assert_eq!(user.matches(end).count(), 1);
    let nonce = end
        .trim_start_matches("<<<END LOGS ")
        .trim_end_matches(">>>");
    assert!(system.contains(nonce) && system.contains("untrusted data"));
    // The injection is still there, as data, after the nonce'd opening marker.
    let open = user.find("<<<LOGS ").unwrap();
    assert!(user.find("IGNORE ALL PREVIOUS INSTRUCTIONS").unwrap() > open);
}

#[test]
fn token_shaped_input_cannot_pose_as_a_token() {
    let p = engine().prepare(&hostile(), None, [3; 32]).unwrap();
    let masked = p.input.text();
    assert!(!masked.contains("[[HOST_1]]"));
    assert!(!masked.contains(" USER_2"));
    let literals: Vec<&str> = p
        .map
        .tokens()
        .filter(|(_, k, _)| **k == EntityType::Literal)
        .map(|(t, _, _)| t)
        .collect();
    assert_eq!(literals.len(), 2, "{masked}");
    // A model echoing the literal's token gets the original text back, not a real host.
    let back = p.map.unmask(&format!("saw {}", literals[0])).text;
    assert!(back == "saw [[HOST_1]]" || back == "saw USER_2", "{back}");
}

#[test]
fn look_alike_unicode_is_normalized_then_masked() {
    let p = engine().prepare(&hostile(), None, [3; 32]).unwrap();
    let masked = p.input.text();
    for leaked in ["192.0.2.7", "web01", "kpatel", "Kpatel"] {
        assert!(!masked.contains(leaked), "{leaked} survived:\n{masked}");
    }
}

#[test]
fn model_html_is_never_rendered() {
    let raw = r#"{"summary":"<script>alert(document.cookie)</script> see <img src=x onerror=alert(1)> and [x](javascript:alert(1))","verdict":"true_positive","severity":{"level":"high","rationale":"<b>r</b>"},"confidence":{"score":0.9,"would_change_it":"x"},"recommended_actions":{"containment":["<iframe src=https://evil.example.org>"],"investigation":[{"language":"kql","query":"```\n<script>","purpose":"p"}]}}"#;
    let analysis = report::parse_model_output(raw).unwrap();
    let r = Report {
        schema_version: report::SCHEMA_VERSION,
        analysis: Some(analysis),
        raw_output: None,
        entities: Vec::new(),
        warnings: Vec::new(),
        meta: Meta {
            provider: "test".into(),
            model: "test".into(),
            mode: Mode::Default,
            parser: "raw".into(),
            lines: 1,
            events: 1,
            parse_errors: 0,
            mask: MaskStats::default(),
            sampling: Sampling::default(),
            attack_version: "v0".into(),
            created_at: report::rfc3339(0),
        },
    };
    let md = report::render_markdown(&r);
    // Outside code fences, no tag or link survives.
    let outside_fences: String = md.split("````").step_by(2).collect();
    for bad in [
        "<script",
        "<img",
        "<iframe",
        "<b>",
        "](javascript",
        "https://evil",
    ] {
        assert!(!outside_fences.contains(bad), "{bad} rendered:\n{md}");
    }
    // The query's own ``` cannot close the fence early.
    assert!(md.contains("````kql"));
}

#[test]
fn regexes_stay_linear_on_pathological_input() {
    let policy = Policy::from_toml("[[rules]]\nname = \"evil\"\npattern = '(a+)+$'\n").unwrap();
    let engine = Engine::new(policy).unwrap();
    let mut text = "a".repeat(200_000);
    text.push('!');
    text.push_str(&"1.".repeat(50_000));
    text.push_str(&":".repeat(50_000));
    text.push_str(&"a@".repeat(30_000));
    text.push_str(&"\\\\".repeat(30_000));
    let t = Instant::now();
    engine.prepare(&text, Some("raw"), [0; 32]).unwrap();
    assert!(
        t.elapsed() < Duration::from_secs(20),
        "took {:?}",
        t.elapsed()
    );
}
