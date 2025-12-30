//! Error types for OTS module

use std::error;
use std::fmt;
use std::io;
use std::string::FromUtf8Error;

/// Maximum recursion depth for timestamp operations
pub const RECURSION_LIMIT: usize = 256;

/// Maximum length of a pending attestation URI
pub const MAX_URI_LEN: usize = 1000;

/// Maximum length of operation data
pub const MAX_OP_LENGTH: usize = 4096;

/// Error type for OTS module operations
#[derive(Debug)]
pub enum OtsError {
    /// Recursion limit exceeded
    StackOverflow,
    /// Invalid character in pending attestation URI
    InvalidUriChar(char),
    /// Unrecognized digest type tag
    BadDigestTag(u8),
    /// Unrecognized operation tag
    BadOpTag(u8),
    /// File doesn't start with OTS magic bytes
    BadMagic(Vec<u8>),
    /// Unsupported OTS file version
    BadVersion(usize),
    /// Byte vector length out of range
    BadLength {
        /// Minimum allowed length
        min: usize,
        /// Maximum allowed length
        max: usize,
        /// Actual value
        val: usize,
    },
    /// Unexpected data after end of timestamp
    TrailingBytes,
    /// UTF-8 decoding error
    Utf8(FromUtf8Error),
    /// I/O error
    Io(io::Error),
}

impl fmt::Display for OtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackOverflow => write!(f, "recursion limit of {} exceeded", RECURSION_LIMIT),
            Self::InvalidUriChar(c) => write!(f, "invalid character '{}' in URI", c),
            Self::BadDigestTag(tag) => write!(f, "unrecognized digest type tag: 0x{:02x}", tag),
            Self::BadOpTag(tag) => write!(f, "unrecognized operation tag: 0x{:02x}", tag),
            Self::BadMagic(bytes) => {
                write!(f, "invalid magic bytes {:?}, is this a timestamp file?", bytes)
            }
            Self::BadVersion(version) => {
                write!(f, "unsupported OTS file version: {}", version)
            }
            Self::BadLength { min, max, val } => {
                write!(f, "length {} is out of range (expected {}-{} inclusive)", val, min, max)
            }
            Self::TrailingBytes => write!(f, "unexpected data after end of timestamp"),
            Self::Utf8(e) => write!(f, "UTF-8 decoding error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl error::Error for OtsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Utf8(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for OtsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<FromUtf8Error> for OtsError {
    fn from(e: FromUtf8Error) -> Self {
        Self::Utf8(e)
    }
}

/// Result type alias for OTS operations
pub type Result<T> = std::result::Result<T, OtsError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_error_display() {
        let err = OtsError::StackOverflow;
        assert_eq!(err.to_string(), "recursion limit of 256 exceeded");

        let err = OtsError::InvalidUriChar('$');
        assert_eq!(err.to_string(), "invalid character '$' in URI");

        let err = OtsError::BadDigestTag(0xFF);
        assert_eq!(err.to_string(), "unrecognized digest type tag: 0xff");

        let err = OtsError::BadOpTag(0xAB);
        assert_eq!(err.to_string(), "unrecognized operation tag: 0xab");

        let err = OtsError::BadMagic(vec![0x00, 0x01, 0x02]);
        assert!(err.to_string().contains("invalid magic bytes"));

        let err = OtsError::BadVersion(2);
        assert_eq!(err.to_string(), "unsupported OTS file version: 2");

        let err = OtsError::BadLength { min: 1, max: 10, val: 20 };
        assert_eq!(err.to_string(), "length 20 is out of range (expected 1-10 inclusive)");

        let err = OtsError::TrailingBytes;
        assert_eq!(err.to_string(), "unexpected data after end of timestamp");
    }

    #[test]
    fn test_error_source() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = OtsError::from(io_err);
        assert!(err.source().is_some());

        let utf8_err = String::from_utf8(vec![0xFF, 0xFE]).unwrap_err();
        let err = OtsError::from(utf8_err);
        assert!(err.source().is_some());

        let err = OtsError::StackOverflow;
        assert!(err.source().is_none());
    }

    #[test]
    fn test_constants() {
        assert_eq!(RECURSION_LIMIT, 256);
        assert_eq!(MAX_URI_LEN, 1000);
        assert_eq!(MAX_OP_LENGTH, 4096);
    }

    #[test]
    fn test_utf8_error_display() {
        let utf8_err = String::from_utf8(vec![0xFF, 0xFE]).unwrap_err();
        let err = OtsError::from(utf8_err);
        let display = format!("{}", err);
        assert!(display.contains("UTF-8 decoding error"));
    }

    #[test]
    fn test_io_error_display() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = OtsError::from(io_err);
        let display = format!("{}", err);
        assert!(display.contains("I/O error"));
        assert!(display.contains("file not found"));
    }

    #[test]
    fn test_error_is_error_trait() {
        // Verify that OtsError implements std::error::Error
        fn assert_error<T: Error>() {}
        assert_error::<OtsError>();
    }

    #[test]
    fn test_error_debug() {
        let err = OtsError::StackOverflow;
        let debug = format!("{:?}", err);
        assert!(debug.contains("StackOverflow"));

        let err = OtsError::BadDigestTag(0x99);
        let debug = format!("{:?}", err);
        assert!(debug.contains("BadDigestTag"));
    }

    #[test]
    fn test_all_error_variants_display() {
        // Ensure all error variants can be displayed without panic
        let errors = vec![
            OtsError::StackOverflow,
            OtsError::InvalidUriChar('#'),
            OtsError::BadDigestTag(0x42),
            OtsError::BadOpTag(0x43),
            OtsError::BadMagic(vec![1, 2, 3]),
            OtsError::BadVersion(99),
            OtsError::BadLength { min: 5, max: 10, val: 3 },
            OtsError::TrailingBytes,
            OtsError::Utf8(String::from_utf8(vec![0xFF]).unwrap_err()),
            OtsError::Io(io::Error::new(io::ErrorKind::Other, "test")),
        ];

        for err in errors {
            let display = format!("{}", err);
            assert!(!display.is_empty(), "Error display should not be empty");
        }
    }

    #[test]
    fn test_result_type_alias() {
        // Test that our Result type alias works correctly
        fn returns_result() -> Result<i32> {
            Ok(42)
        }

        fn returns_error() -> Result<i32> {
            Err(OtsError::StackOverflow)
        }

        assert_eq!(returns_result().unwrap(), 42);
        assert!(returns_error().is_err());
    }
}
