//! Sudare in the browser: the same engine as the server, run locally in the page.
//! [`mask`] is the playground. [`Session`] is a whole analysis: the mask map stays in
//! wasm memory, JavaScript only ever gets masked prompts out and passes the model's raw
//! reply back in. The network call to the provider is the page's, not this crate's.
#![forbid(unsafe_code)]

use serde_json::{Value, json};
use std::sync::LazyLock;
use sudare_core::analysis::{self, Begun};
use sudare_core::prompt::{self, ChatTurn, MaskedPrompt};
use sudare_core::{Engine, MaskedText, Policy, Prepared};
use wasm_bindgen::prelude::*;

/// [default mode, strict mode], built once.
static ENGINES: LazyLock<[Engine; 2]> = LazyLock::new(|| {
    let p = Policy::default();
    [
        Engine::new(p.clone()).expect("default policy is valid"),
        Engine::new(p.strict()).expect("strict policy is valid"),
    ]
});

fn prepare(
    text: &str,
    strict: bool,
    parser: Option<&str>,
    salt: &[u8],
) -> Result<Prepared, JsError> {
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| JsError::new("salt must be 32 bytes"))?;
    ENGINES[usize::from(strict)]
        .prepare(text, parser, salt)
        .map_err(|e| JsError::new(&e.to_string()))
}

fn preview(p: &Prepared) -> String {
    json!({
        "masked": p.input.text(),
        "parser": p.parser,
        "lines": p.input.line_count(),
        "events": p.events,
        "parse_errors": p.parse_errors,
        "stats": p.stats,
        "public_indicators": p.indicators.len(),
        "decisions": p.decisions,
    })
    .to_string()
}

fn messages(p: &MaskedPrompt) -> Value {
    serde_json::to_value(p.messages()).expect("messages serialize")
}

/// Mask `text`. `salt` must be 32 fresh random bytes (crypto.getRandomValues).
/// Returns JSON: masked text, stats and every decision (value, action, token).
#[wasm_bindgen]
pub fn mask(
    text: &str,
    strict: bool,
    parser: Option<String>,
    salt: &[u8],
) -> Result<String, JsError> {
    Ok(preview(&prepare(text, strict, parser.as_deref(), salt)?))
}

/// JSON list of `{name, description}`.
#[wasm_bindgen]
pub fn parsers() -> String {
    let list: Vec<_> = ENGINES[0]
        .registry()
        .parsers()
        .map(|p| json!({ "name": p.name(), "description": p.description() }))
        .collect();
    Value::from(list).to_string()
}

/// One analysis and its follow-up chat.
#[wasm_bindgen]
pub struct Session {
    strict: bool,
    prepared: Prepared,
    begun: Option<Begun>,
    masked_output: Option<String>,
    history: Vec<ChatTurn>,
    question: Option<MaskedText>,
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(constructor)]
    pub fn new(
        text: &str,
        strict: bool,
        parser: Option<String>,
        salt: &[u8],
    ) -> Result<Session, JsError> {
        Ok(Session {
            strict,
            prepared: prepare(text, strict, parser.as_deref(), salt)?,
            begun: None,
            masked_output: None,
            history: Vec::new(),
            question: None,
        })
    }

    fn engine(&self) -> &'static Engine {
        &ENGINES[usize::from(self.strict)]
    }

    /// Same JSON as [`mask`], for the review step.
    pub fn preview(&self) -> String {
        preview(&self.prepared)
    }

    /// JSON `{messages: [{role, content}], schema}`, masked. Rule fields are optional.
    pub fn analysis_prompt(
        &mut self,
        max_input_chars: usize,
        rule_name: Option<String>,
        rule_condition: Option<String>,
    ) -> String {
        let rule = rule_name.map(|n| (n, rule_condition.unwrap_or_default()));
        let begun = analysis::begin(
            self.engine(),
            &mut self.prepared,
            &[],
            rule.as_ref(),
            max_input_chars,
        );
        let out = json!({ "messages": messages(&begun.prompt), "schema": begun.schema });
        self.begun = Some(begun);
        out.to_string()
    }

    /// Messages to send again when `raw` isn't a valid analysis; `undefined` when it is.
    pub fn retry_prompt(&self, raw: &str) -> Option<String> {
        let begun = self.begun.as_ref()?;
        analysis::retry(begun, raw).map(|p| messages(&p).to_string())
    }

    /// The report as JSON, with real values restored. `now_unix` is seconds.
    pub fn finish(
        &mut self,
        raw: &str,
        provider: &str,
        model: &str,
        now_unix: f64,
    ) -> Result<String, JsError> {
        let begun = self
            .begun
            .take()
            .ok_or_else(|| JsError::new("call analysis_prompt first"))?;
        let report = analysis::finish(
            self.engine(),
            &self.prepared,
            &[],
            begun,
            raw,
            provider,
            model,
            now_unix.max(0.0) as u64,
        );
        self.masked_output = Some(raw.to_string());
        Ok(serde_json::to_string(&report).expect("report serializes"))
    }

    /// JSON `{question, messages}` for a follow-up, both masked: show `question` for review.
    pub fn chat_prompt(
        &mut self,
        question: &str,
        max_input_chars: usize,
    ) -> Result<String, JsError> {
        let masked_output = self
            .masked_output
            .as_deref()
            .ok_or_else(|| JsError::new("finish the analysis first"))?;
        let q = self.engine().mask_followup(&mut self.prepared, question);
        let p = prompt::chat(
            &self.prepared.input,
            &self.prepared.map,
            masked_output,
            &self.history,
            &q,
            max_input_chars,
        );
        let out = json!({ "question": q.as_str(), "messages": messages(&p) });
        self.question = Some(q);
        Ok(out.to_string())
    }

    /// The answer with real values restored; records the turn.
    pub fn chat_answer(&mut self, raw: &str) -> Result<String, JsError> {
        let question = self
            .question
            .take()
            .ok_or_else(|| JsError::new("call chat_prompt first"))?;
        let answer = self.prepared.map.unmask(raw).text;
        self.history.push(ChatTurn {
            question,
            answer: raw.to_string(),
        });
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "<38>Oct 29 15:01:02 bastion01 sshd[4242]: Failed password for jdoe from 10.20.30.40 port 22 ssh2";

    #[test]
    fn masks_internal_values_and_rejects_bad_salt() {
        let out = mask(LOG, false, None, &[7; 32]).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let masked = v["masked"].as_str().unwrap();
        assert!(
            !masked.contains("10.20.30.40") && !masked.contains("jdoe"),
            "{masked}"
        );
        assert!(masked.contains("[[IP_INTERNAL_"), "{masked}");
        assert!(parsers().contains("syslog"));
    }

    #[test]
    fn session_round_trip_never_exposes_real_values() {
        let mut s = Session::new(LOG, false, None, &[7; 32]).unwrap();
        let prompt = s.analysis_prompt(100_000, None, None);
        assert!(!prompt.contains("jdoe") && !prompt.contains("10.20.30.40"));
        let v: Value = serde_json::from_str(&prompt).unwrap();
        let user = v["messages"][1]["content"].as_str().unwrap();
        let token = &user[user.find("[[USER_").unwrap()..];
        let token = &token[..token.find("]]").unwrap() + 2];

        assert!(s.retry_prompt("not json").is_some());
        let raw = json!({
            "summary": format!("{token} failed to log in"),
            "verdict": "benign",
            "severity": { "level": "low", "rationale": "r" },
            "confidence": { "score": 0.5, "would_change_it": "x" },
            "recommended_actions": {}
        })
        .to_string();
        assert!(s.retry_prompt(&raw).is_none());
        let report = s.finish(&raw, "gemini", "m", 1_793_232_000.0).unwrap();
        assert!(report.contains("jdoe failed to log in"), "{report}");

        let chat = s.chat_prompt("what did jdoe do?", 100_000).unwrap();
        assert!(!chat.contains("jdoe"), "{chat}");
        let answer = s.chat_answer(&format!("{token} tried a password")).unwrap();
        assert_eq!(answer, "jdoe tried a password");
    }
}
