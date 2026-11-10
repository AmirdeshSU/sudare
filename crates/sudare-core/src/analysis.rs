//! The offline half of an analysis. [`begin`] builds the masked prompt; [`finish`]
//! validates, unmasks and assembles the report. The LLM call in between belongs to the
//! caller: `sudare-egress` natively, the browser through `sudare-wasm`.

use crate::prompt::{self, MaskedPrompt, PromptInputs, Sampling};
use crate::report::{self, EnrichmentResult, Meta, Report, ReportEntity, TiStatus, Warning};
use crate::{Engine, EntityType, IndicatorKind, Prepared, Scope, attack};

/// A built prompt, waiting for the model's reply.
pub struct Begun {
    pub prompt: MaskedPrompt,
    /// JSON schema for structured output.
    pub schema: serde_json::Value,
    sampling: Sampling,
    warnings: Vec<Warning>,
}

/// Threat-intel facts for the prompt, keyed by token when the value is masked.
fn ti_notes(prepared: &Prepared, results: &[Vec<EnrichmentResult>]) -> Option<String> {
    let mut lines = Vec::new();
    for (ind, rs) in prepared.indicators.iter().zip(results) {
        let subject = ind.token().unwrap_or(ind.value());
        for r in rs.iter().filter(|r| r.status == TiStatus::Ok) {
            let verdict = r
                .verdict
                .map(|v| format!("{v:?}").to_lowercase())
                .unwrap_or_default();
            let facts = r.facts.join("; ").replace('\n', " ");
            lines.push(format!("{subject} | {} | {verdict} | {facts}", r.provider));
        }
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

fn indicator_kind(kind: &EntityType, scope: Scope) -> Option<IndicatorKind> {
    match (kind, scope) {
        (EntityType::Ip, Scope::Public) => Some(IndicatorKind::Ip),
        (EntityType::Fqdn, Scope::Public) => Some(IndicatorKind::Domain),
        (EntityType::Url, Scope::Public) => Some(IndicatorKind::Url),
        (EntityType::Md5 | EntityType::Sha1 | EntityType::Sha256, _) => Some(IndicatorKind::Hash),
        _ => None,
    }
}

/// `enrichment` is one result list per `prepared.indicators` entry (may be empty).
/// `rule` is the detection rule's name and condition, if the alert came from one.
pub fn begin(
    engine: &Engine,
    prepared: &mut Prepared,
    enrichment: &[Vec<EnrichmentResult>],
    rule: Option<&(String, String)>,
    max_input_chars: usize,
) -> Begun {
    let ti = ti_notes(prepared, enrichment).map(|t| engine.mask_followup(prepared, &t));
    let rule = rule.map(|(name, cond)| {
        engine.mask_followup(prepared, &format!("name: {name}\ncondition: {cond}"))
    });
    let schema = report::model_schema();
    let schema_text = serde_json::to_string(&schema).expect("schema serializes");
    let inputs = PromptInputs {
        max_input_chars,
        rule: rule.as_ref(),
        threat_intel: ti.as_ref(),
    };
    let (prompt, sampling) =
        prompt::analysis(&prepared.input, &prepared.map, &schema_text, &inputs);

    let mut warnings = Vec::new();
    if sampling.sampled {
        warnings.push(Warning::new(
            "input_sampled",
            format!(
                "{} of {} events sent (rarest types first) to fit the context budget",
                sampling.events_shown, sampling.events_total
            ),
        ));
    }
    if prepared.parse_errors > 0 {
        warnings.push(Warning::new(
            "parse_errors",
            format!(
                "{} of {} records could not be parsed as {}; their text was still masked and sent",
                prepared.parse_errors, prepared.events, prepared.parser
            ),
        ));
    }
    Begun {
        prompt,
        schema,
        sampling,
        warnings,
    }
}

/// The prompt to send again when `raw` isn't a valid analysis; `None` when it is.
pub fn retry(begun: &Begun, raw: &str) -> Option<MaskedPrompt> {
    report::parse_model_output(raw)
        .err()
        .map(|e| prompt::retry(&begun.prompt, raw, &e))
}

/// `raw` is the model's final reply (after at most one [`retry`]).
#[allow(clippy::too_many_arguments)]
pub fn finish(
    engine: &Engine,
    prepared: &Prepared,
    enrichment: &[Vec<EnrichmentResult>],
    begun: Begun,
    raw: &str,
    provider: &str,
    model: &str,
    now_unix: u64,
) -> Report {
    let mut warnings = begun.warnings;
    let analysis = match report::parse_model_output(raw) {
        Ok(mut a) => {
            warnings.extend(report::validate(&mut a, &prepared.input, &prepared.map));
            let (a, unknown) = report::unmask_analysis(&a, &prepared.map);
            if !unknown.is_empty() {
                warnings.push(Warning::new(
                    "unknown_token",
                    format!(
                        "placeholders not from this input, left as-is: {}",
                        unknown.join(", ")
                    ),
                ));
            }
            Some(a)
        }
        Err(e) => {
            warnings.push(Warning::new(
                "invalid_model_output",
                format!("no valid JSON after one retry: {e}"),
            ));
            None
        }
    };
    let raw_output = analysis.is_none().then(|| prepared.map.unmask(raw).text);

    let entities = prepared
        .decisions
        .iter()
        .map(|d| {
            let e = &d.entity;
            let enrichment = indicator_kind(&e.kind, e.scope)
                .and_then(|k| {
                    prepared.indicators.iter().position(|i| {
                        i.kind() == k && (i.value() == e.normalized || i.value() == e.value)
                    })
                })
                .and_then(|i| enrichment.get(i).cloned())
                .unwrap_or_default();
            ReportEntity {
                value: e.value.clone(),
                kind: e.kind.clone(),
                scope: e.scope,
                action: d.action,
                token: d.token.clone(),
                enrichment,
            }
        })
        .collect();

    Report {
        schema_version: report::SCHEMA_VERSION,
        analysis,
        raw_output,
        entities,
        warnings,
        meta: Meta {
            provider: provider.into(),
            model: model.into(),
            mode: engine.policy().mode,
            parser: prepared.parser.clone(),
            lines: prepared.input.line_count(),
            events: prepared.events,
            parse_errors: prepared.parse_errors,
            mask: prepared.stats.clone(),
            sampling: begun.sampling,
            attack_version: attack::index().version().into(),
            created_at: report::rfc3339(now_unix),
        },
    }
}
