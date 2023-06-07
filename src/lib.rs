#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

//! Docs require the `nightly` feature until RFC 1990 lands.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod batch;
mod error;
mod signing_key;
mod verification_key;

// Allows importing traits used by `Signature`.
pub use ed25519;
pub use ed25519::Signature;
pub use error::Error;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
