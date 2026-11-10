//! Everything that leaves the machine goes through this crate, and only through the
//! [`http::Http`] trait, so tests can record every byte. LLM providers accept only a
//! [`sudare_core::MaskedPrompt`]; threat-intel providers only a
//! [`sudare_core::PublicIndicator`]. SIEM connectors ([`siem`]) send only credentials and
//! an incident id, to the SIEM you configure.
#![forbid(unsafe_code)]

pub mod cache;
pub mod http;
pub mod llm;
pub mod pipeline;
pub mod siem;
pub mod ti;
