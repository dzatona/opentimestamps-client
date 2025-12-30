//! Attestation types for OpenTimestamps
//!
//! An attestation is a claim that some data existed at some time.

use std::fmt;
use std::io::{Read, Write};

use super::error::{OtsError, Result, MAX_URI_LEN};
use super::ser::{Deserializer, Serializer};

/// Size in bytes of the tag identifying the attestation type
pub const TAG_SIZE: usize = 8;

/// Tag indicating a Bitcoin attestation
pub const BITCOIN_TAG: &[u8] = b"\x05\x88\x96\x0d\x73\xd7\x19\x01";

/// Tag indicating a pending attestation
pub const PENDING_TAG: &[u8] = b"\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e";

/// An attestation that some data existed at some time
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Attestation {
    /// An attestation from a Bitcoin blockheader.
    /// This consists of a blockheight and nothing more.
    Bitcoin {
        /// The Bitcoin block height
        height: usize,
    },
    /// An attestation from some server.
    /// The server should be expected to keep anything it attests to forever.
    Pending {
        /// The URI where the attestation can be updated
        uri: String,
    },
    /// An unknown attestation type that we store as-is
    Unknown {
        /// The attestation type tag
        tag: Vec<u8>,
        /// The attestation data
        data: Vec<u8>,
    },
}

impl Attestation {
    /// Deserialize an arbitrary attestation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tag is invalid
    /// - The URI contains invalid characters
    /// - Deserialization fails
    pub fn deserialize<R: Read>(deser: &mut Deserializer<R>) -> Result<Self> {
        let tag = deser.read_fixed_bytes(TAG_SIZE)?;
        let len = deser.read_uint()?;

        if tag == BITCOIN_TAG {
            let height = deser.read_uint()?;
            Ok(Self::Bitcoin { height })
        } else if tag == PENDING_TAG {
            // This validation logic ensures URI contains only safe characters
            let uri_bytes = deser.read_bytes(0, MAX_URI_LEN)?;
            let uri_string = String::from_utf8(uri_bytes)?;
            for ch in uri_string.chars() {
                match ch {
                    'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | '/' | ':' => {}
                    x => return Err(OtsError::InvalidUriChar(x)),
                }
            }
            Ok(Self::Pending { uri: uri_string })
        } else {
            Ok(Self::Unknown { tag, data: deser.read_fixed_bytes(len)? })
        }
    }

    /// Serialize an attestation
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn serialize<W: Write>(&self, ser: &mut Serializer<W>) -> Result<()> {
        let mut byte_ser = Serializer::new(Vec::new());
        match *self {
            Self::Bitcoin { height } => {
                ser.write_fixed_bytes(BITCOIN_TAG)?;
                byte_ser.write_uint(height)?;
                ser.write_bytes(&byte_ser.into_inner())
            }
            Self::Pending { ref uri } => {
                ser.write_fixed_bytes(PENDING_TAG)?;
                byte_ser.write_bytes(uri.as_bytes())?;
                ser.write_bytes(&byte_ser.into_inner())
            }
            Self::Unknown { ref tag, ref data } => {
                ser.write_fixed_bytes(tag)?;
                ser.write_bytes(data)
            }
        }
    }
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitcoin { height } => write!(f, "Bitcoin block {}", height),
            Self::Pending { uri } => write!(f, "Pending: update URI {}", uri),
            Self::Unknown { tag, data } => {
                write!(f, "unknown attestation type {}: {}", hex::encode(tag), hex::encode(data))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_display() {
        let attestation = Attestation::Bitcoin { height: 123456 };
        assert_eq!(format!("{}", attestation), "Bitcoin block 123456");
    }

    #[test]
    fn test_pending_display() {
        let attestation = Attestation::Pending { uri: "https://example.com/calendar".to_string() };
        assert_eq!(format!("{}", attestation), "Pending: update URI https://example.com/calendar");
    }

    #[test]
    fn test_unknown_display() {
        let attestation = Attestation::Unknown {
            tag: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            data: vec![0xaa, 0xbb, 0xcc],
        };
        let display = format!("{}", attestation);
        assert!(display.starts_with("unknown attestation type"));
        assert!(display.contains("0102030405060708"));
        assert!(display.contains("aabbcc"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(TAG_SIZE, 8);
        assert_eq!(BITCOIN_TAG.len(), 8);
        assert_eq!(PENDING_TAG.len(), 8);
        assert_eq!(BITCOIN_TAG, b"\x05\x88\x96\x0d\x73\xd7\x19\x01");
        assert_eq!(PENDING_TAG, b"\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e");
    }

    #[test]
    fn test_clone_and_equality() {
        let attestation1 = Attestation::Bitcoin { height: 100 };
        let attestation2 = attestation1.clone();
        assert_eq!(attestation1, attestation2);

        let attestation3 = Attestation::Pending { uri: "https://test.com".to_string() };
        let attestation4 = attestation3.clone();
        assert_eq!(attestation3, attestation4);

        assert_ne!(attestation1, attestation3);
    }

    #[test]
    fn test_serialize_deserialize_bitcoin() {
        let attestation = Attestation::Bitcoin { height: 654321 };
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        attestation.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_pending() {
        let attestation = Attestation::Pending {
            uri: "https://alice.btc.calendar.opentimestamps.org".to_string(),
        };
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        attestation.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_unknown() {
        let attestation = Attestation::Unknown {
            tag: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            data: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        attestation.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_deserialize_invalid_uri_char() {
        // Create a pending attestation with invalid character
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        // Write PENDING_TAG
        ser.write_fixed_bytes(PENDING_TAG).unwrap();
        // Write length prefix (outer length for attestation data)
        let uri_with_invalid = b"https://test.com/$invalid";
        let mut inner_buf = Vec::new();
        let mut inner_ser = Serializer::new(&mut inner_buf);
        inner_ser.write_bytes(uri_with_invalid).unwrap();
        let inner_data = inner_ser.into_inner();
        ser.write_bytes(inner_data).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = Attestation::deserialize(&mut deser);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::InvalidUriChar('$')));
    }

    #[test]
    fn test_deserialize_valid_uri_chars() {
        // Test that all valid URI characters are accepted
        let valid_uri = "https://test-server.com:8080/path/to_resource.ext";
        let attestation = Attestation::Pending { uri: valid_uri.to_string() };
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        attestation.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_deserialize_empty_uri() {
        // Test empty URI (should be valid, length 0 is within 0..MAX_URI_LEN)
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_fixed_bytes(PENDING_TAG).unwrap();
        let mut inner_buf = Vec::new();
        let mut inner_ser = Serializer::new(&mut inner_buf);
        inner_ser.write_bytes(b"").unwrap();
        let inner_data = inner_ser.into_inner();
        ser.write_bytes(inner_data).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(result, Attestation::Pending { uri: String::new() });
    }

    #[test]
    fn test_bitcoin_height_zero() {
        let attestation = Attestation::Bitcoin { height: 0 };
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        attestation.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_bitcoin_large_height() {
        let attestation = Attestation::Bitcoin { height: 1_000_000 };
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        attestation.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_unknown_empty_data() {
        let attestation = Attestation::Unknown { tag: vec![0xff; 8], data: vec![] };
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        attestation.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(attestation, deserialized);
    }
}
