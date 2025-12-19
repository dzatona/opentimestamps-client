//! OpenTimestamps core types and operations module
//!
//! This module contains all the core types needed for OTS file parsing,
//! timestamp verification, and attestation handling.

mod attestation;
mod digest;
mod error;
mod op;
mod ser;
mod timestamp;

pub use attestation::*;
pub use digest::*;
pub use error::*;
pub use op::*;
pub use ser::*;
pub use timestamp::*;
