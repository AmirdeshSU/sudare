//! Sudare core: parse → extract → classify → mask → prompt → validate → unmask.
//!
//! This crate never touches the network; CI fails if a networking crate shows up in
//! its dependency tree. The privacy rules live in the types:
//! - [`MaskedText`], [`MaskedInput`] and [`MaskedPrompt`] can only be built by the masker,
//!   and LLM providers only accept a [`MaskedPrompt`].
//! - [`PublicIndicator`] can only be built from a public-scope entity whose text holds
//!   no masked value, and threat-intel providers only accept that type.
#![forbid(unsafe_code)]

pub mod analysis;
pub mod attack;
pub mod classify;
pub mod engine;
pub mod extract;
pub mod mask;
pub mod normalize;
pub mod parse;
pub mod policy;
pub mod prompt;
pub mod report;
pub mod types;

pub use engine::{Engine, Prepared, SealError};
pub use mask::{IndicatorKind, MaskMap, MaskStats, MaskedInput, MaskedText, PublicIndicator};
pub use policy::{Action, Mode, Policy};
pub use prompt::{ChatMessage, ChatTurn, MaskedPrompt, Role};
pub use types::{Entity, EntityType, Event, Scope, Span};
