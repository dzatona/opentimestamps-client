//! # Operations
//!
//! Operations that can be performed on data in an OpenTimestamps proof.
//! Each operation takes input bytes and produces output bytes.

use std::fmt;
use std::io::{Read, Write};

use bitcoin_hashes::{ripemd160, sha1, sha256, Hash};

use super::error::{OtsError, Result, MAX_OP_LENGTH};
use super::ser::{Deserializer, Serializer};

/// All the types of operations supported
#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(missing_docs)]
pub enum Op {
    /// SHA-1 hash operation
    Sha1,
    /// SHA-256 hash operation
    Sha256,
    /// RIPEMD-160 hash operation
    Ripemd160,
    /// Convert bytes to hexadecimal string
    Hexlify,
    /// Reverse byte order
    Reverse,
    /// Append data to the end
    Append(Vec<u8>),
    /// Prepend data to the beginning
    Prepend(Vec<u8>),
}

impl Op {
    /// Returns the 8-bit tag identifying the op in binary format
    pub fn tag(&self) -> u8 {
        match *self {
            Op::Sha1 => 0x02,
            Op::Sha256 => 0x08,
            Op::Ripemd160 => 0x03,
            Op::Hexlify => 0xf3,
            Op::Reverse => 0xf2,
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1,
        }
    }

    /// Execute the operation on the given input data
    pub fn execute(&self, input: &[u8]) -> Vec<u8> {
        match *self {
            Op::Sha1 => sha1::Hash::hash(input).to_byte_array().to_vec(),
            Op::Sha256 => sha256::Hash::hash(input).to_byte_array().to_vec(),
            Op::Ripemd160 => ripemd160::Hash::hash(input).to_byte_array().to_vec(),
            Op::Hexlify => hex::encode(input).into_bytes(),
            Op::Reverse => input.iter().copied().rev().collect(),
            Op::Append(ref data) => {
                let mut vec = input.to_vec();
                vec.extend(data);
                vec
            }
            Op::Prepend(ref data) => {
                let mut vec = data.to_vec();
                vec.extend(input);
                vec
            }
        }
    }

    /// Deserialize an arbitrary op
    ///
    /// # Errors
    ///
    /// Returns an error if the tag is not recognized or deserialization fails
    #[allow(dead_code)]
    pub fn deserialize<R: Read>(deser: &mut Deserializer<R>) -> Result<Self> {
        let tag = deser.read_byte()?;
        Self::deserialize_with_tag(deser, tag)
    }

    /// Deserialize an op with the designated tag
    ///
    /// # Errors
    ///
    /// Returns `OtsError::BadOpTag` if the tag is not recognized
    pub fn deserialize_with_tag<R: Read>(deser: &mut Deserializer<R>, tag: u8) -> Result<Self> {
        match tag {
            // unary ops are trivial
            0x02 => Ok(Self::Sha1),
            0x08 => Ok(Self::Sha256),
            0x03 => Ok(Self::Ripemd160),
            0xf3 => Ok(Self::Hexlify),
            0xf2 => Ok(Self::Reverse),
            // binary ops need to read data
            0xf0 => Ok(Self::Append(deser.read_bytes(1, MAX_OP_LENGTH)?)),
            0xf1 => Ok(Self::Prepend(deser.read_bytes(1, MAX_OP_LENGTH)?)),
            x => Err(OtsError::BadOpTag(x)),
        }
    }

    /// Serialize the op into a serializer
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn serialize<W: Write>(&self, ser: &mut Serializer<W>) -> Result<()> {
        ser.write_byte(self.tag())?;
        if let Self::Append(ref data) = *self {
            ser.write_bytes(data)?;
        }
        if let Self::Prepend(ref data) = *self {
            ser.write_bytes(data)?;
        }
        Ok(())
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Op::Sha1 => f.write_str("SHA1()"),
            Op::Sha256 => f.write_str("SHA256()"),
            Op::Ripemd160 => f.write_str("RIPEMD160()"),
            Op::Hexlify => f.write_str("Hexlify()"),
            Op::Reverse => f.write_str("Reverse()"),
            Op::Append(ref data) => write!(f, "Append({})", hex::encode(data)),
            Op::Prepend(ref data) => write!(f, "Prepend({})", hex::encode(data)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_values() {
        assert_eq!(Op::Sha1.tag(), 0x02);
        assert_eq!(Op::Sha256.tag(), 0x08);
        assert_eq!(Op::Ripemd160.tag(), 0x03);
        assert_eq!(Op::Hexlify.tag(), 0xf3);
        assert_eq!(Op::Reverse.tag(), 0xf2);
        assert_eq!(Op::Append(vec![]).tag(), 0xf0);
        assert_eq!(Op::Prepend(vec![]).tag(), 0xf1);
    }

    #[test]
    fn test_sha256_execute() {
        let input = b"hello";
        let result = Op::Sha256.execute(input);
        // Expected SHA256 hash of "hello"
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha1_execute() {
        let input = b"hello";
        let result = Op::Sha1.execute(input);
        // Expected SHA1 hash of "hello"
        let expected = hex::decode("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_ripemd160_execute() {
        let input = b"hello";
        let result = Op::Ripemd160.execute(input);
        // Expected RIPEMD160 hash of "hello"
        let expected = hex::decode("108f07b8382412612c048d07d13f814118445acd").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_append_execute() {
        let input = b"hello";
        let append_data = vec![0x01, 0x02, 0x03];
        let result = Op::Append(append_data.clone()).execute(input);
        assert_eq!(result, b"hello\x01\x02\x03");
    }

    #[test]
    fn test_prepend_execute() {
        let input = b"world";
        let prepend_data = vec![0x01, 0x02, 0x03];
        let result = Op::Prepend(prepend_data.clone()).execute(input);
        assert_eq!(result, b"\x01\x02\x03world");
    }

    #[test]
    fn test_reverse_execute() {
        let input = b"hello";
        let result = Op::Reverse.execute(input);
        assert_eq!(result, b"olleh");
    }

    #[test]
    fn test_hexlify_execute() {
        let input = b"\x01\x02\x03\xff";
        let result = Op::Hexlify.execute(input);
        assert_eq!(result, b"010203ff");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Op::Sha1), "SHA1()");
        assert_eq!(format!("{}", Op::Sha256), "SHA256()");
        assert_eq!(format!("{}", Op::Ripemd160), "RIPEMD160()");
        assert_eq!(format!("{}", Op::Hexlify), "Hexlify()");
        assert_eq!(format!("{}", Op::Reverse), "Reverse()");
        assert_eq!(format!("{}", Op::Append(vec![0x01, 0x02, 0x03])), "Append(010203)");
        assert_eq!(format!("{}", Op::Prepend(vec![0xaa, 0xbb])), "Prepend(aabb)");
    }

    #[test]
    fn test_clone_and_equality() {
        let op1 = Op::Sha256;
        let op2 = op1.clone();
        assert_eq!(op1, op2);

        let op3 = Op::Append(vec![1, 2, 3]);
        let op4 = op3.clone();
        assert_eq!(op3, op4);
    }

    #[test]
    fn test_serialize_deserialize_unary_ops() {
        let ops = vec![Op::Sha1, Op::Sha256, Op::Ripemd160, Op::Hexlify, Op::Reverse];

        for op in ops {
            let mut buf = Vec::new();
            let mut ser = Serializer::new(&mut buf);
            op.serialize(&mut ser).unwrap();

            let mut deser = Deserializer::new(&buf[..]);
            let deserialized = Op::deserialize(&mut deser).unwrap();
            assert_eq!(op, deserialized);
        }
    }

    #[test]
    fn test_serialize_deserialize_append() {
        let op = Op::Append(vec![0xaa, 0xbb, 0xcc]);
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        op.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Op::deserialize(&mut deser).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_prepend() {
        let op = Op::Prepend(vec![0x01, 0x02, 0x03, 0x04]);
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        op.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Op::deserialize(&mut deser).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_deserialize_with_tag_invalid() {
        let buf = Vec::new();
        let mut deser = Deserializer::new(&buf[..]);
        let result = Op::deserialize_with_tag(&mut deser, 0xFF);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::BadOpTag(0xFF)));
    }

    #[test]
    fn test_deserialize_with_tag_all_valid() {
        // Test all valid unary op tags
        for (tag, expected_op) in [
            (0x02, Op::Sha1),
            (0x08, Op::Sha256),
            (0x03, Op::Ripemd160),
            (0xf3, Op::Hexlify),
            (0xf2, Op::Reverse),
        ] {
            let buf = Vec::new();
            let mut deser = Deserializer::new(&buf[..]);
            let result = Op::deserialize_with_tag(&mut deser, tag).unwrap();
            assert_eq!(result, expected_op);
        }
    }

    #[test]
    fn test_deserialize_append_with_tag() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        // Write length and data for Append
        ser.write_bytes(&[0xaa, 0xbb]).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = Op::deserialize_with_tag(&mut deser, 0xf0).unwrap();
        assert_eq!(result, Op::Append(vec![0xaa, 0xbb]));
    }

    #[test]
    fn test_deserialize_prepend_with_tag() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        // Write length and data for Prepend
        ser.write_bytes(&[0x11, 0x22, 0x33]).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = Op::deserialize_with_tag(&mut deser, 0xf1).unwrap();
        assert_eq!(result, Op::Prepend(vec![0x11, 0x22, 0x33]));
    }

    #[test]
    fn test_execute_empty_input() {
        // Test operations with empty input
        let empty = b"";
        assert_eq!(Op::Sha256.execute(empty).len(), 32);
        assert_eq!(Op::Sha1.execute(empty).len(), 20);
        assert_eq!(Op::Ripemd160.execute(empty).len(), 20);
        assert_eq!(Op::Reverse.execute(empty), empty);
        assert_eq!(Op::Hexlify.execute(empty), b"");
    }

    #[test]
    fn test_append_empty_data() {
        let input = b"test";
        let result = Op::Append(vec![]).execute(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_prepend_empty_data() {
        let input = b"test";
        let result = Op::Prepend(vec![]).execute(input);
        assert_eq!(result, input);
    }
}
