//! analyze = prompt → LLM → validate (one retry) → unmask → report.

use crate::http::Http;
use crate::llm::{LlmError, LlmProvider};
use crate::ti::TiRunner;
use sudare_core::prompt::{self, ChatTurn};
use sudare_core::report::{EnrichmentResult, Report};
use sudare_core::{Engine, Prepared, analysis};

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

pub async fn analyze(
    engine: &Engine,
    prepared: &mut Prepared,
    enrichment: &[Vec<EnrichmentResult>],
    provider: &dyn LlmProvider,
    http: &dyn Http,
    opts: &AnalyzeOptions,
) -> Result<Analysis, LlmError> {
    let budget = opts.max_input_chars.unwrap_or(provider.context_chars());
    let begun = analysis::begin(engine, prepared, enrichment, opts.rule.as_ref(), budget);
    let first = provider
        .complete(&begun.prompt, Some(&begun.schema), http)
        .await?;
    let (mut model, mut raw) = (first.model, first.text);
    if let Some(retry) = analysis::retry(&begun, &raw) {
        let second = provider.complete(&retry, Some(&begun.schema), http).await?;
        (model, raw) = (second.model, second.text);
    }
    let report = analysis::finish(
        engine,
        prepared,
        enrichment,
        begun,
        &raw,
        provider.name(),
        &model,
        opts.now_unix,
    );
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
