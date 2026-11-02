//! Ties the core steps together: normalize → parse → extract → classify → mask.

use crate::classify::Classifier;
use crate::mask::{
    Decision, EventRef, MaskMap, MaskStats, MaskedInput, MaskedText, Masker, PublicIndicator,
};
use crate::normalize::{LineIndex, normalize};
use crate::parse::{Parser, Raw, Registry};
use crate::policy::{Policy, PolicyError};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("unknown parser {0:?}; run `sudare parsers` to list them")]
    UnknownParser(String),
}

pub struct Engine {
    registry: Registry,
    masker: Masker,
    classifier: Classifier,
}

/// Everything produced before the LLM call. Stays on this machine: it holds the
/// real values (`normalized`, `decisions`, `map`).
#[derive(Debug)]
pub struct Prepared {
    pub parser: String,
    pub normalized: String,
    pub input: MaskedInput,
    pub map: MaskMap,
    pub decisions: Vec<Decision>,
    pub indicators: Vec<PublicIndicator>,
    pub stats: MaskStats,
    pub events: usize,
    pub parse_errors: usize,
    classifier: Classifier,
}

impl Engine {
    pub fn new(policy: Policy) -> Result<Self, PolicyError> {
        let classifier = Classifier::new(&policy.networks()?, &policy.classify.internal_domains);
        Ok(Self {
            registry: Registry::builtin(),
            masker: Masker::new(policy)?,
            classifier,
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut Registry {
        &mut self.registry
    }

    pub fn policy(&self) -> &Policy {
        self.masker.policy()
    }

    /// Fixtures use documentation ranges as stand-ins for public addresses.
    #[doc(hidden)]
    pub fn documentation_ranges_public(mut self) -> Self {
        self.classifier = self.classifier.documentation_ranges_public();
        self
    }

    /// `salt` must be fresh random bytes for every analysis.
    pub fn prepare(
        &self,
        raw: &str,
        parser: Option<&str>,
        salt: [u8; 32],
    ) -> Result<Prepared, EngineError> {
        let text = normalize(raw);
        let parser: &dyn Parser = match parser {
            Some(name) => self
                .registry
                .get(name)
                .ok_or_else(|| EngineError::UnknownParser(name.to_string()))?,
            None => self.registry.detect(&text),
        };
        let events = parser.parse(&text);

        let mut entities = Vec::new();
        for x in self.masker.extractors(parser) {
            x.extract(&text, &events, &mut entities);
        }

        let mut classifier = self.classifier.clone();
        if self.policy().classify.learn_internal_domains {
            for e in &events {
                for f in parser.self_fields() {
                    if let Some(v) = e.fields.get(&f) {
                        classifier.learn_domain(v);
                    }
                }
            }
        }
        for e in &mut entities {
            e.scope = classifier.scope(e);
        }

        let mut map = MaskMap::new(salt);
        let applied = self.masker.apply(&text, entities, &mut map);
        let input = MaskedInput {
            lines: LineIndex::new(&text).count(),
            events: events
                .iter()
                .map(|e| EventRef {
                    lines: e.lines,
                    group: parser.group_key(e),
                })
                .collect(),
            text: applied.text,
        };
        Ok(Prepared {
            parser: parser.name().to_string(),
            normalized: text,
            input,
            map,
            decisions: applied.decisions,
            indicators: applied.indicators,
            stats: applied.stats,
            events: events.len(),
            parse_errors: events.iter().filter(|e| e.error.is_some()).count(),
            classifier,
        })
    }

    /// Mask more text (a chat question, a rule, threat-intel notes) with the same map,
    /// so a value keeps its token across the whole conversation.
    pub fn mask_followup(&self, prepared: &mut Prepared, text: &str) -> MaskedText {
        let text = normalize(text);
        let events = Raw.parse(&text);
        let mut entities = Vec::new();
        for x in self.masker.extractors(&Raw) {
            x.extract(&text, &events, &mut entities);
        }
        for e in &mut entities {
            e.scope = prepared.classifier.scope(e);
        }
        let applied = self.masker.apply(&text, entities, &mut prepared.map);
        MaskedText(applied.text)
    }
}
