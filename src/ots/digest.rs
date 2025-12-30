//! Digest types supported by OpenTimestamps

use std::fmt;

use super::error::{OtsError, Result};

/// Cryptographic digest algorithms supported by OpenTimestamps
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DigestType {
    /// SHA-1 hash (20 bytes)
    Sha1,
    /// SHA-256 hash (32 bytes)
    Sha256,
    /// RIPEMD-160 hash (20 bytes)
    Ripemd160,
}

impl DigestType {
    /// Create a DigestType from a tag byte
    ///
    /// # Errors
    ///
    /// Returns `OtsError::BadDigestTag` if the tag is not recognized
    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0x02 => Ok(Self::Sha1),
            0x03 => Ok(Self::Ripemd160),
            0x08 => Ok(Self::Sha256),
            _ => Err(OtsError::BadDigestTag(tag)),
        }
    }

    /// Convert the digest type to its tag byte
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Sha1 => 0x02,
            Self::Ripemd160 => 0x03,
            Self::Sha256 => 0x08,
        }
    }

    /// Get the length in bytes of this digest type
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 | Self::Ripemd160 => 20,
            Self::Sha256 => 32,
        }
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => f.write_str("SHA1"),
            Self::Sha256 => f.write_str("SHA256"),
            Self::Ripemd160 => f.write_str("RIPEMD160"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_tag() {
        assert_eq!(DigestType::from_tag(0x02).unwrap(), DigestType::Sha1);
        assert_eq!(DigestType::from_tag(0x03).unwrap(), DigestType::Ripemd160);
        assert_eq!(DigestType::from_tag(0x08).unwrap(), DigestType::Sha256);
        assert!(DigestType::from_tag(0xFF).is_err());
    }

    #[test]
    fn test_to_tag() {
        assert_eq!(DigestType::Sha1.to_tag(), 0x02);
        assert_eq!(DigestType::Ripemd160.to_tag(), 0x03);
        assert_eq!(DigestType::Sha256.to_tag(), 0x08);
    }

    #[test]
    fn test_digest_len() {
        assert_eq!(DigestType::Sha1.digest_len(), 20);
        assert_eq!(DigestType::Ripemd160.digest_len(), 20);
        assert_eq!(DigestType::Sha256.digest_len(), 32);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", DigestType::Sha1), "SHA1");
        assert_eq!(format!("{}", DigestType::Sha256), "SHA256");
        assert_eq!(format!("{}", DigestType::Ripemd160), "RIPEMD160");
    }

    #[test]
    fn test_round_trip() {
        for digest_type in [DigestType::Sha1, DigestType::Sha256, DigestType::Ripemd160] {
            let tag = digest_type.to_tag();
            assert_eq!(DigestType::from_tag(tag).unwrap(), digest_type);
        }
    }

    #[test]
    fn test_from_tag_all_invalid() {
        // Test various invalid tags
        for invalid_tag in [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x09, 0xFF] {
            assert!(DigestType::from_tag(invalid_tag).is_err());
        }
    }

    #[test]
    fn test_digest_type_equality() {
        assert_eq!(DigestType::Sha1, DigestType::Sha1);
        assert_eq!(DigestType::Sha256, DigestType::Sha256);
        assert_eq!(DigestType::Ripemd160, DigestType::Ripemd160);
        assert_ne!(DigestType::Sha1, DigestType::Sha256);
        assert_ne!(DigestType::Sha256, DigestType::Ripemd160);
    }

    #[test]
    fn test_digest_type_clone() {
        let dt = DigestType::Sha256;
        let cloned = dt;
        assert_eq!(dt, cloned);
    }

    #[test]
    fn test_digest_type_copy() {
        let dt1 = DigestType::Sha256;
        let dt2 = dt1; // This should work because DigestType is Copy
        assert_eq!(dt1, dt2);
    }

    #[test]
    fn test_digest_type_debug() {
        let dt = DigestType::Sha256;
        let debug = format!("{:?}", dt);
        assert!(debug.contains("Sha256"));
    }

    #[test]
    fn test_from_tag_error_contains_tag() {
        let result = DigestType::from_tag(0x99);
        assert!(result.is_err());
        match result.unwrap_err() {
            super::super::error::OtsError::BadDigestTag(tag) => assert_eq!(tag, 0x99),
            _ => panic!("Expected BadDigestTag error"),
        }
    }
}
