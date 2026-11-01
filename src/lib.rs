//! Fast PII and secret masking. See `README.md` for the Python API.

mod engine;
#[cfg(feature = "python")]
mod python;
mod rules;

pub use engine::{ConfigError, Masker, MaskerConfig, Span};
pub use rules::ENTITIES;
