#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

//! Docs require the `nightly` feature until RFC 1990 lands.

pub mod batch;
mod error;
mod signature;
mod signing_key;
mod verification_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
