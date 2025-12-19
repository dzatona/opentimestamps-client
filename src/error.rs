use thiserror::Error;

/// Main error type for the `OpenTimestamps` client
#[derive(Error, Debug)]
pub enum Error {
    /// IO error occurred
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid OTS file format
    #[error("Invalid OTS file: {0}")]
    InvalidOts(#[from] opentimestamps::error::Error),

    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Calendar server error
    #[error("Calendar error: {0}")]
    Calendar(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    Verification(String),

    /// No Bitcoin attestation found in timestamp
    #[error("No Bitcoin attestation found")]
    NoBitcoinAttestation,

    /// Timestamp is pending, not yet confirmed on Bitcoin blockchain
    #[error("Timestamp is pending, not yet confirmed")]
    PendingTimestamp,
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, Error>;
