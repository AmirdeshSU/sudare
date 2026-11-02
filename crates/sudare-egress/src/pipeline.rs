//! analyze = prompt → LLM → validate (one retry) → unmask → report.

use crate::http::Http;
use crate::llm::{LlmError, LlmProvider};
use crate::ti::TiRunner;
use sudare_core::prompt::{self, ChatTurn, PromptInputs};
use sudare_core::report::{self, EnrichmentResult, Meta, Report, ReportEntity, TiStatus, Warning};
use sudare_core::{Engine, EntityType, IndicatorKind, Prepared, Scope, attack};

pub struct AnalyzeOptions {
    /// Detection rule name and condition, if the alert came from one.
    pub rule: Option<(String, String)>,
    pub max_input_chars: Option<usize>,
    pub now_unix: u64,
}

pub struct Analysis {
    pub report: Report,
    /// The model's reply before unmasking; chat continues from it.
    pub masked_output: String,
}

pub async fn enrich(
    prepared: &Prepared,
    runner: &TiRunner,
    http: &dyn Http,
) -> Vec<Vec<EnrichmentResult>> {
    runner.enrich(&prepared.indicators, http).await
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

pub async fn analyze(
    engine: &Engine,
    prepared: &mut Prepared,
    enrichment: &[Vec<EnrichmentResult>],
    provider: &dyn LlmProvider,
    http: &dyn Http,
    opts: &AnalyzeOptions,
) -> Result<Analysis, LlmError> {
    let ti = ti_notes(prepared, enrichment).map(|t| engine.mask_followup(prepared, &t));
    let rule = opts.rule.as_ref().map(|(name, cond)| {
        engine.mask_followup(prepared, &format!("name: {name}\ncondition: {cond}"))
    });
    let schema = report::model_schema();
    let schema_text = serde_json::to_string(&schema).expect("schema serializes");
    let inputs = PromptInputs {
        max_input_chars: opts.max_input_chars.unwrap_or(provider.context_chars()),
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

    let first = provider.complete(&prompt, Some(&schema), http).await?;
    let mut model = first.model;
    let mut raw = first.text;
    let mut parsed = report::parse_model_output(&raw);
    if let Err(e) = &parsed {
        let retry = prompt::retry(&prompt, &raw, e);
        let second = provider.complete(&retry, Some(&schema), http).await?;
        model = second.model;
        raw = second.text;
        parsed = report::parse_model_output(&raw);
    }

    let analysis = match parsed {
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
    let raw_output = analysis.is_none().then(|| prepared.map.unmask(&raw).text);

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

    let report = Report {
        schema_version: report::SCHEMA_VERSION,
        analysis,
        raw_output,
        entities,
        warnings,
        meta: Meta {
            provider: provider.name().into(),
            model,
            mode: engine.policy().mode,
            parser: prepared.parser.clone(),
            lines: prepared.input.line_count(),
            events: prepared.events,
            parse_errors: prepared.parse_errors,
            mask: prepared.stats.clone(),
            sampling,
            attack_version: attack::index().version().into(),
            created_at: report::rfc3339(opts.now_unix),
        },
    };
    Ok(Analysis {
        report,
        masked_output: raw,
    })
}

/// One follow-up question on the same masked context and map. Returns the unmasked answer.
#[allow(clippy::too_many_arguments)]
pub async fn chat(
    engine: &Engine,
    prepared: &mut Prepared,
    masked_output: &str,
    history: &mut Vec<ChatTurn>,
    question: &str,
    provider: &dyn LlmProvider,
    http: &dyn Http,
    max_input_chars: Option<usize>,
) -> Result<String, LlmError> {
    let q = engine.mask_followup(prepared, question);
    let budget = max_input_chars.unwrap_or(provider.context_chars());
    let p = prompt::chat(
        &prepared.input,
        &prepared.map,
        masked_output,
        history,
        &q,
        budget,
    );
    let r = provider.complete(&p, None, http).await?;
    let answer = prepared.map.unmask(&r.text).text;
    history.push(ChatTurn {
        question: q,
        answer: r.text,
    });
    Ok(answer)
}
