//! Ties the core steps together: normalize → parse → extract → classify → mask.

use crate::classify::Classifier;
use crate::mask::{
    Decision, EventRef, MaskMap, MaskStats, MaskedInput, MaskedText, Masker, PublicIndicator,
};
use crate::normalize::{LineIndex, normalize};
use crate::parse::{Parser, Raw, Registry};
use crate::policy::{Policy, PolicyError};
use crate::prompt::ChatTurn;

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
    /// Follow-up questions and answers, both masked. Sealed with the session.
    pub chat: Vec<ChatTurn>,
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
            chat: Vec::new(),
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

/// Sealed sessions: `SDR1 || nonce(24) || XChaCha20-Poly1305(JSON)`. The only way the
/// mask map is ever serialized.
const SEAL_MAGIC: &[u8; 4] = b"SDR1";
const SEAL_AAD: &[u8] = b"sudare-session-v1";

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("sealed session is malformed")]
    Malformed,
    #[error("sealed session failed to decrypt (wrong key or tampered)")]
    Decrypt,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionState {
    salt: [u8; 32],
    parser: String,
    entries: Vec<crate::mask::SealedEntry>,
    input: MaskedInput,
    classifier: Classifier,
    /// (masked question, masked answer)
    chat: Vec<(String, String)>,
}

impl Prepared {
    /// Encrypt what chat needs later: the map, the masked input and the learned
    /// classifier. `nonce` must be fresh random bytes for every call.
    pub fn seal(&self, key: &[u8; 32], nonce: [u8; 24]) -> Vec<u8> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use zeroize::Zeroize;
        let state = SessionState {
            salt: self.map.salt(),
            parser: self.parser.clone(),
            entries: self.map.export(),
            input: self.input.clone(),
            classifier: self.classifier.clone(),
            chat: self
                .chat
                .iter()
                .map(|t| (t.question.as_str().to_string(), t.answer.clone()))
                .collect(),
        };
        let mut plain = serde_json::to_vec(&state).expect("session serializes");
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(&(*key).into());
        let sealed = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plain,
                    aad: SEAL_AAD,
                },
            )
            .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
        plain.zeroize();
        let mut out = Vec::with_capacity(4 + 24 + sealed.len());
        out.extend_from_slice(SEAL_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        out
    }

    /// Reopen a sealed session for chat. The report-time fields (`normalized`,
    /// `decisions`, `indicators`, `stats`) come back empty.
    pub fn open(sealed: &[u8], key: &[u8; 32]) -> Result<Prepared, SealError> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use zeroize::Zeroize;
        if sealed.len() < 4 + 24 + 16 || &sealed[..4] != SEAL_MAGIC {
            return Err(SealError::Malformed);
        }
        let nonce: [u8; 24] = sealed[4..28].try_into().map_err(|_| SealError::Malformed)?;
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(&(*key).into());
        let mut plain = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &sealed[28..],
                    aad: SEAL_AAD,
                },
            )
            .map_err(|_| SealError::Decrypt)?;
        let state: Result<SessionState, _> = serde_json::from_slice(&plain);
        plain.zeroize();
        let state = state.map_err(|_| SealError::Malformed)?;
        Ok(Prepared {
            parser: state.parser,
            normalized: String::new(),
            events: state.input.events.len(),
            map: MaskMap::import(state.salt, &state.entries),
            input: state.input,
            decisions: Vec::new(),
            indicators: Vec::new(),
            stats: MaskStats::default(),
            parse_errors: 0,
            chat: state
                .chat
                .into_iter()
                .map(|(q, answer)| ChatTurn {
                    question: MaskedText(q),
                    answer,
                })
                .collect(),
            classifier: state.classifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip_and_tamper_detection() {
        let engine = Engine::new(Policy::default()).unwrap();
        let mut p = engine
            .prepare("user=jdoe host=fw01 from 10.1.2.3", None, [4; 32])
            .unwrap();
        let sealed = p.seal(&[9; 32], [1; 24]);
        let blob = String::from_utf8_lossy(&sealed);
        assert!(!blob.contains("jdoe") && !blob.contains("10.1.2.3"));

        let mut back = Prepared::open(&sealed, &[9; 32]).unwrap();
        assert_eq!(back.input.text(), p.input.text());
        let token = p
            .map
            .tokens()
            .find(|(_, k, _)| **k == crate::EntityType::Username)
            .unwrap()
            .0
            .to_string();
        assert_eq!(back.map.unmask(&token).text, "jdoe");
        // Follow-ups reuse the same tokens after reopening.
        let a = engine.mask_followup(&mut p, "is fw01 compromised?");
        let b = engine.mask_followup(&mut back, "is fw01 compromised?");
        assert_eq!(a.as_str(), b.as_str());

        assert!(matches!(
            Prepared::open(&sealed, &[8; 32]),
            Err(SealError::Decrypt)
        ));
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            Prepared::open(&tampered, &[9; 32]),
            Err(SealError::Decrypt)
        ));
        assert!(matches!(
            Prepared::open(b"nope", &[9; 32]),
            Err(SealError::Malformed)
        ));
    }
}
