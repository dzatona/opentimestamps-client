//! Serialization and deserialization for OpenTimestamps files
//!
//! This module provides tools for reading and writing OTS timestamp files.

use std::fmt;
use std::io::{Read, Write};

use super::digest::DigestType;
use super::error::{OtsError, Result};
use super::timestamp::Timestamp;

/// Magic bytes that every OTS proof must start with
pub const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

/// Major version of timestamp files we understand
pub const VERSION: usize = 1;

/// Structure representing a detached timestamp file
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DetachedTimestampFile {
    /// The claimed hash function used to produce the document digest
    pub digest_type: DigestType,
    /// The actual timestamp data
    pub timestamp: Timestamp,
}

impl DetachedTimestampFile {
    /// Deserialize a timestamp file from a reader
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The magic bytes are invalid
    /// - The version is unsupported
    /// - The file format is invalid
    /// - There is trailing data after the timestamp
    pub fn from_reader<R: Read>(reader: R) -> Result<Self> {
        let mut deser = Deserializer::new(reader);

        deser.read_magic()?;
        deser.read_version()?;
        let digest_type = DigestType::from_tag(deser.read_byte()?)?;
        let digest = deser.read_fixed_bytes(digest_type.digest_len())?;
        let timestamp = Timestamp::deserialize(&mut deser, digest)?;

        deser.check_eof()?;

        Ok(Self { digest_type, timestamp })
    }

    /// Serialize the timestamp file into a writer
    ///
    /// # Errors
    ///
    /// Returns an error if any I/O operation fails
    pub fn to_writer<W: Write>(&self, writer: W) -> Result<()> {
        let mut ser = Serializer::new(writer);
        ser.write_magic()?;
        ser.write_version()?;
        ser.write_byte(self.digest_type.to_tag())?;
        // We write timestamp.start_digest here and not in `Timestamp::serialize`
        // to copy the way that python-opentimestamps is structured
        ser.write_fixed_bytes(&self.timestamp.start_digest)?;
        self.timestamp.serialize(&mut ser)
    }
}

impl fmt::Display for DetachedTimestampFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} digest of some data.", self.digest_type)?;
        write!(f, "{}", self.timestamp)
    }
}

/// Standard deserializer for OTS timestamp files
pub struct Deserializer<R: Read> {
    reader: R,
}

impl<R: Read> Deserializer<R> {
    /// Constructs a new deserializer from a reader
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Extracts the underlying reader from the deserializer
    #[must_use]
    #[allow(dead_code)]
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Reads the magic bytes and checks that they match the expected value
    ///
    /// # Errors
    ///
    /// Returns `OtsError::BadMagic` if the magic bytes don't match
    pub fn read_magic(&mut self) -> Result<()> {
        let recv_magic = self.read_fixed_bytes(MAGIC.len())?;
        if recv_magic == MAGIC {
            Ok(())
        } else {
            Err(OtsError::BadMagic(recv_magic))
        }
    }

    /// Reads the version and checks that it matches the expected value
    ///
    /// # Errors
    ///
    /// Returns `OtsError::BadVersion` if the version is not supported
    pub fn read_version(&mut self) -> Result<()> {
        let recv_version = self.read_uint()?;
        if recv_version == VERSION {
            Ok(())
        } else {
            Err(OtsError::BadVersion(recv_version))
        }
    }

    /// Reads a single byte from the reader
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails
    pub fn read_byte(&mut self) -> Result<u8> {
        let mut byte = [0];
        self.reader.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    /// Deserializes an unsigned integer using LEB128 variable-length encoding
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails
    pub fn read_uint(&mut self) -> Result<usize> {
        let mut ret = 0;
        let mut shift = 0;

        loop {
            // Bottom 7 bits are value bits
            let byte = self.read_byte()?;
            ret |= ((byte & 0x7f) as usize) << shift;
            // Top bit is a continue bit
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }

        Ok(ret)
    }

    /// Deserializes a fixed number of bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails
    pub fn read_fixed_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut ret = vec![0; n];
        self.reader.read_exact(&mut ret)?;
        Ok(ret)
    }

    /// Deserializes a variable number of bytes with length prefix
    ///
    /// # Errors
    ///
    /// Returns `OtsError::BadLength` if the length is out of range
    pub fn read_bytes(&mut self, min: usize, max: usize) -> Result<Vec<u8>> {
        let n = self.read_uint()?;
        if n < min || n > max {
            return Err(OtsError::BadLength { min, max, val: n });
        }
        self.read_fixed_bytes(n)
    }

    /// Check that there is no trailing data after the timestamp
    ///
    /// # Errors
    ///
    /// Returns `OtsError::TrailingBytes` if there is data after the end
    #[allow(clippy::unbuffered_bytes)]
    pub fn check_eof(&mut self) -> Result<()> {
        use std::io::Read as _;
        if self.reader.by_ref().bytes().next().is_none() {
            Ok(())
        } else {
            Err(OtsError::TrailingBytes)
        }
    }
}

/// Standard serializer for OTS timestamp files
pub struct Serializer<W: Write> {
    writer: W,
}

impl<W: Write> Serializer<W> {
    /// Constructs a new serializer from a writer
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Extracts the underlying writer from the serializer
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Writes the magic bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_magic(&mut self) -> Result<()> {
        self.write_fixed_bytes(MAGIC)
    }

    /// Writes the major version
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_version(&mut self) -> Result<()> {
        self.write_uint(VERSION)
    }

    /// Writes a single byte to the writer
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_byte(&mut self, byte: u8) -> Result<()> {
        self.writer.write_all(&[byte])?;
        Ok(())
    }

    /// Write an unsigned integer using LEB128 variable-length encoding
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_uint(&mut self, mut n: usize) -> Result<()> {
        if n == 0 {
            self.write_byte(0x00)
        } else {
            while n > 0 {
                if n > 0x7f {
                    self.write_byte((n as u8) | 0x80)?;
                } else {
                    self.write_byte(n as u8)?;
                }
                n >>= 7;
            }
            Ok(())
        }
    }

    /// Write a fixed number of bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_fixed_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Write a variable number of bytes with length prefix
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.write_uint(data.len())?;
        self.write_fixed_bytes(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from rust-opentimestamps
    const SMALL_TEST: &[u8] = b"\
\x00\x4f\x70\x65\x6e\x54\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x00\x00\x50\x72\x6f\x6f\x66\x00\xbf\x89\xe2\xe8\x84\xe8\x92\
\x94\x01\x08\xa7\x0d\xfe\x69\xc5\xa0\xd6\x28\x16\x78\x1a\xbb\x6e\x17\x77\x85\x47\x18\x62\x4a\x0d\x19\x42\x31\xad\xb1\x4c\
\x32\xee\x54\x38\xa4\xf0\x10\x7a\x46\x05\xde\x0a\x5b\x37\xcb\x21\x17\x59\xc6\x81\x2b\xfe\x2e\x08\xff\xf0\x10\x24\x4b\x79\
\xd5\x78\xaa\x38\xe3\x4f\x42\x7b\x0f\x3e\xd2\x55\xa5\x08\xf1\x04\x58\xa4\xc2\x57\xf0\x08\xa1\xa9\x2c\x61\xd5\x41\x72\x06\
\x00\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x2c\x2b\x68\x74\x74\x70\x73\x3a\x2f\x2f\x62\x6f\x62\x2e\x62\x74\x63\x2e\x63\x61\x6c\
\x65\x6e\x64\x61\x72\x2e\x6f\x70\x65\x6e\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x2e\x6f\x72\x67\xf0\x10\xe0\x27\x85\x91\
\xe2\x88\x68\x19\xba\x7b\x3d\xdd\x63\x2e\xd3\xfe\x08\xf1\x04\x58\xa4\xc2\x56\xf0\x08\x38\xf2\xc7\xf4\xba\xf4\xbc\xd7\x00\
\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x2e\x2d\x68\x74\x74\x70\x73\x3a\x2f\x2f\x61\x6c\x69\x63\x65\x2e\x62\x74\x63\x2e\x63\x61\
\x6c\x65\x6e\x64\x61\x72\x2e\x6f\x70\x65\x6e\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x2e\x6f\x72\x67";

    const LARGE_TEST: &[u8] = b"\
\x00\x4f\x70\x65\x6e\x54\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x00\x00\x50\x72\x6f\x6f\x66\x00\xbf\x89\xe2\xe8\x84\xe8\x92\
\x94\x01\x08\x6f\xd9\xc1\xc4\xf0\x96\xb7\x7e\x6d\x44\x57\xba\xc1\xc7\xf5\x10\x10\xd3\x18\xdb\x48\x3f\x28\x68\xd3\x79\x58\
\x43\xf0\x98\xd3\x78\xf0\x10\xe2\xe2\x24\x43\x9e\x7f\x0f\xdd\x8c\x1e\xea\xc7\x3e\xa7\x39\xdb\x08\xf1\x20\xa5\x74\x44\x4a\
\xa5\x00\x02\xb6\xfe\x5a\xf2\x46\x26\x70\x0a\x4b\xfc\x95\x0d\x61\xf8\x13\x7c\xc3\x9d\xa8\x2d\x53\x27\x6c\x9d\x66\x08\xf0\
\x20\x02\xf3\x1f\xd5\xa2\xf0\xff\x08\xf7\xe0\x73\x38\x4b\x4f\xf5\x2b\xc5\xa0\x26\xf6\xfe\x42\x4a\x3b\x6c\x83\x58\x0e\x76\
\x9e\x59\xd2\x08\xf0\x20\xe0\xea\x0a\x32\x87\xcc\xb1\x0f\x39\x1c\x62\xf6\x8e\xb5\xa2\xde\x1d\x13\xbc\x24\xc5\xc0\xb4\x0f\
\x6a\x03\xe3\x6b\xbb\xa7\xaa\xb0\x08\xf0\x20\xd9\xc3\xfa\x8a\x65\xbb\x0c\xcf\xb3\x38\x5c\xc2\x03\x42\x05\x94\xe2\xe5\xa9\
\x34\x41\xbf\xf8\x5c\xcc\x53\xd1\x63\x9b\x0f\x2c\x85\x08\xf0\x20\x2f\xc4\x1f\x43\xb7\xab\xb0\x51\xf2\xe9\xee\x08\x39\xb8\
\x61\x9a\xd8\xc7\xb0\xc4\x04\xcd\xfc\xcd\xd5\xd0\x90\xbb\x3b\x42\xa8\x89\x08\xf0\x20\x0b\xae\x5b\x64\x92\x16\x89\xf7\xb3\
\xee\x1f\x86\xb1\xae\x79\xea\x7e\xd3\xd8\x22\x08\x4f\x3a\x2c\xed\xb3\x75\xd1\xc2\x36\x05\x93\x08\xf1\x20\xe9\x31\xb8\x22\
\x28\xdb\x72\xb4\x9e\x9c\x33\x9c\x3f\xd8\xa2\x48\x16\x26\x48\xc3\x0e\x3c\x03\x1d\xb5\x40\x20\x76\xf4\xe1\x9d\x48\x08\xf1\
\x20\x37\xe1\x51\xfe\x09\x9e\x20\x8f\x90\xfe\x51\x11\x65\x0f\x81\x38\xdf\xd3\x2f\xa8\x5f\x21\x30\xf1\x6c\xd5\xe9\x91\xb4\
\xf9\x48\x1c\x08\xff\xf0\x10\x2c\x2b\xd1\x10\x61\x89\x89\xd9\xa4\xc6\xbf\x60\xa8\xde\xec\x50\x08\xf1\x04\x58\x83\xf1\x71\
\xf0\x08\x6d\x45\x80\xfc\x64\xdf\xa9\x79\xff\x00\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x2c\x2b\x68\x74\x74\x70\x73\x3a\x2f\x2f\
\x62\x6f\x62\x2e\x62\x74\x63\x2e\x63\x61\x6c\x65\x6e\x64\x61\x72\x2e\x6f\x70\x65\x6e\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\
\x73\x2e\x6f\x72\x67\x08\xf1\xae\x01\x01\x00\x00\x00\x01\x7e\x85\x5c\xd0\x5c\xb2\x31\x1f\xea\x5f\xed\xde\xea\x21\xbe\x34\
\xa5\x98\x2e\xb3\xfb\xa9\xbd\xca\x1d\x9e\xf9\x8a\x80\x05\xe1\x22\x00\x00\x00\x00\x48\x47\x30\x44\x02\x20\x3d\x4d\xec\x68\
\x13\xb7\xe2\x87\x0e\xc5\x38\xb3\x88\x2c\xd0\x5e\x5d\xb5\x71\xd7\x51\x1b\x6e\x31\x98\x69\x46\x2b\x02\x9f\xf2\x5a\x02\x20\
\x3e\xeb\x26\x3b\x36\x1a\x2b\x48\x20\xe9\x9c\xed\xce\xa1\x47\x1a\xcd\x4b\xee\x47\x3a\x23\xa8\x2f\xaf\xcf\xf1\xbe\x13\x15\
\xb3\x45\x01\xfd\xff\xff\xff\x02\xe3\x14\x13\x00\x00\x00\x00\x00\x23\x21\x02\x76\x18\xa4\x61\xfd\x2d\x26\xc4\xba\x77\xf1\
\xf7\xcd\x8a\xc5\x57\x7e\xea\x66\x5f\xfb\xc9\xa8\xde\x3c\x2e\x55\x91\x1c\xf0\x9f\x73\xac\x00\x00\x00\x00\x00\x00\x00\x00\
\x22\x6a\x20\xf0\x04\x73\xdb\x06\x00\x08\x08\xf0\x20\xa3\xb9\x56\xff\xca\xc2\x63\xfb\xd6\x6b\x33\x1e\x9c\x06\xa4\xb0\x96\
\x34\x2c\xff\xa7\x5a\xc8\x09\x90\x50\xd8\xda\x1c\x14\x94\x10\x08\x08\xf1\x20\x6c\x3c\x90\x80\x96\x2b\x36\x5f\xc4\x3e\x1f\
\xc6\x10\xe6\x91\x23\x7e\x33\x3e\x59\x98\xf8\xa8\x5d\xe3\xac\xf5\x79\x3c\x7d\x7d\x96\x08\x08\xf1\x20\x13\x88\x3d\x43\x52\
\xa3\x8a\x7f\x1b\xe2\xf4\x3a\xe3\x8d\xc3\x8f\xd4\x75\x39\xe4\xf1\xb1\x43\x90\xbe\x7d\x27\x0b\xb3\xf8\x1d\x4e\x08\x08\xf1\
\x20\x86\xe1\xb5\x77\xf7\xc7\xa1\xfd\x34\x52\x92\x81\xba\xcd\xec\x29\x3d\xa4\xd8\xac\xe8\x62\x2a\x6c\x04\xd9\x99\x05\x7d\
\x8b\x8e\x62\x08\x08\xf0\x20\xbf\x6b\x64\xf8\x33\x89\x98\x5d\x0a\xf4\xf7\xb4\x75\x3b\xb6\x8e\x57\x09\xff\xf1\x00\xa3\xdb\
\x0c\xb6\x1e\x6e\x44\xff\x8c\xf6\xae\x08\x08\xf1\x20\xfa\x8b\x54\x69\x92\xb6\x1c\xe2\xf1\xa9\x2f\x82\xde\x54\x5d\xae\x0d\
\xa7\x03\xef\x93\x2b\x6e\x4b\xda\x52\x3f\x2a\xec\x61\x7e\x5f\x08\x08\xf0\x20\x25\x61\xe8\xf4\xc2\x4d\x32\xc2\x14\x1c\x74\
\x64\x6d\xb0\x67\x30\x7f\x6c\x6e\x17\x05\xa4\xf5\x05\xb8\xab\x81\xaf\x1c\x16\x54\xc2\x08\x08\xf1\x20\x51\x7a\x29\xcb\x81\
\x52\x6f\x3b\x28\x71\x6f\xff\xb2\x4d\x5c\x8b\x6d\x6c\xcc\xd4\xb9\x8e\xec\xc9\xaa\xf0\x00\x37\x08\xb4\x25\x22\x08\x08\x00\
\x05\x88\x96\x0d\x73\xd7\x19\x01\x03\xf7\xb6\x1b\xf0\x10\x75\x85\xd6\x34\x8e\x2c\x8a\x1c\x7e\xd0\xa6\x97\x7a\xe4\xd2\xad\
\x08\xf1\x04\x58\x83\xf1\x71\xf0\x08\x5d\xeb\x89\x67\x36\x2e\x06\xb6\xff\x00\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x2e\x2d\x68\
\x74\x74\x70\x73\x3a\x2f\x2f\x61\x6c\x69\x63\x65\x2e\x62\x74\x63\x2e\x63\x61\x6c\x65\x6e\x64\x61\x72\x2e\x6f\x70\x65\x6e\
\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x2e\x6f\x72\x67\x08\xf0\x20\x41\x41\x13\x62\xbc\xe1\x8d\x16\xff\x66\x0b\x43\x1a\
\x64\x4b\xb6\xc4\xa1\xf0\x65\x55\x62\x7a\xe0\x07\x8c\x7b\xb7\x21\x48\x0e\x4b\x08\xf0\x20\xd8\x68\x49\x86\xc4\x82\x11\x22\
\xca\x9f\x66\x6c\x55\x07\xb8\x9d\x89\x6b\x81\x2b\xbe\xc9\xc1\x84\x72\x09\x96\x4d\x0c\x4f\x2e\xc3\x08\xf1\x20\xb1\x07\xd6\
\x20\x2e\x7f\x79\xca\x83\x99\x17\xda\xdb\xeb\x20\x5b\x76\x16\x83\xb4\x9d\x16\x9d\xe2\x30\x25\x45\x2b\xf5\x79\x6a\xe2\x08\
\xf0\x20\x74\xc4\x8c\x02\x9d\x2f\x8f\x5f\xd7\x40\x9e\x8f\xcf\x68\x4e\x42\xbe\xb7\x2e\xbd\x99\xfe\x6c\xef\xff\x09\xe4\x47\
\x29\x49\x06\xa7\x08\xf0\x20\x62\x9e\xe2\x17\x44\x93\x5b\x51\x8c\x36\x14\x8a\xd3\x0f\xc7\xfc\x08\x87\x89\xc2\xb0\x00\xb4\
\x69\xcb\xb5\x0a\xe6\x1a\x34\xf3\x01\x08\xf1\xae\x01\x01\x00\x00\x00\x01\xa2\xc7\x0a\xd9\x76\x8b\x47\x6e\xb8\x2e\x07\x04\
\x75\x60\x3c\xdc\xb3\x01\x41\x4f\x62\xd5\x58\x10\x06\x13\x72\x41\x2d\x91\xe1\xbf\x00\x00\x00\x00\x48\x47\x30\x44\x02\x20\
\x52\x52\xd2\x89\x09\x05\x5e\xff\x8f\xb3\xab\x68\xf9\xcc\x11\x15\x03\x2b\x75\xe6\xcc\xfb\xf3\x84\x4b\xd9\x16\x14\xdd\x73\
\x7c\xd6\x02\x20\x21\xad\xd2\xd0\xab\x18\x8f\x4d\xb5\x55\x06\x6b\x0c\x38\x22\xd4\xba\xb0\x13\x43\x91\x98\x57\xdb\xaa\x11\
\x11\x5d\xc1\x4a\xd2\x21\x01\xfd\xff\xff\xff\x02\xb4\x4d\x44\x00\x00\x00\x00\x00\x23\x21\x03\x00\x9a\x9a\x91\x2d\x43\x76\
\x26\x8e\xc1\x37\x7c\x12\xd3\xd9\x9b\xd5\x1d\xa4\xf1\xed\xd8\x2c\x22\x74\xfd\x45\xde\xe1\xe3\xac\xd1\xac\x00\x00\x00\x00\
\x00\x00\x00\x00\x22\x6a\x20\xf0\x04\x74\xdb\x06\x00\x08\x08\xf1\x20\x5a\xbb\xb3\xdc\xd1\x24\x9e\xeb\x6d\x9b\xa9\x97\x2a\
\x94\x6e\xef\x2c\xdc\x3f\x32\x50\x38\xc1\x9d\x25\x3f\x5c\xa6\xd6\x93\x83\x7b\x08\x08\xf1\x20\xe9\x89\x14\x1b\xe1\x09\xac\
\xba\x19\x78\x20\xe1\x8a\xd9\xc2\x50\x64\x5c\xc0\x9d\xa5\x32\x89\x5e\xd9\x8d\x19\x1f\xf6\xf4\x24\xd6\x08\x08\xf0\x20\x48\
\xdc\xfc\x2f\xe8\x9e\x46\x4e\xd5\x28\x31\x90\x16\x56\xa1\x3b\x9f\x8d\x78\x37\xd6\xba\xe3\xfc\xa1\x8f\x14\x4a\xe0\x03\x73\
\x50\x08\x08\xf1\x20\xb2\x42\x65\xa8\x06\x99\xfd\x93\x01\xd5\x94\xfd\x90\x25\x9b\xd0\xed\x3b\x86\x8a\xf1\xcd\x36\x42\x08\
\x84\x7e\x64\x80\xb8\xab\x57\x08\x08\xf1\x20\xd0\xa7\x95\x39\xe4\x40\xf9\x9e\xe6\x0d\xba\xdd\x27\xa0\x71\x62\x25\x52\x37\
\x14\x0e\x91\x1b\xd0\x1d\xfc\x5c\xde\xc6\xdc\xaf\xec\x08\x08\xf1\x20\xd5\x6d\xf3\x0e\x00\xef\x52\xc8\xd4\xc2\x7e\x95\xe7\
\x7e\x28\xe4\x2e\x8d\xb9\xdb\xf4\x93\x3b\xd3\xc1\xfa\x80\x3c\x79\x2c\x68\xfa\x08\x08\xf1\x20\x91\xe3\x57\x66\xb6\xcf\x6d\
\x60\xd4\xeb\x6f\xa7\x28\xc6\x87\x6e\xca\xbf\x99\x92\x81\xc8\x2e\xd2\x00\xb0\x5a\xb1\x18\x78\xab\x49\x08\x08\xf0\x20\xad\
\x0c\xbb\x07\xe6\xa6\xa3\x59\xf8\x0f\x69\xa8\x7d\xcb\xc9\xbc\x78\x04\x79\xea\x73\xd2\xbe\xb6\xf7\x3c\xd3\xb9\x25\xa2\x89\
\x41\x08\x08\xf1\x20\x4b\x38\x70\x93\xad\xcd\xe0\xb6\x91\x58\xcf\x5d\x08\xdf\xf0\xf6\x2a\xa9\x4c\x77\x41\x52\xad\xa3\x9f\
\xed\x89\x57\x63\xf6\xad\xb3\x08\x08\xf1\x20\xe1\xc1\xae\xc4\x3e\x4c\xba\x0c\xc7\x6a\xed\xf0\x74\x33\xc2\x45\xaf\x3f\x8a\
\xe2\xc0\x56\x45\xa1\x9c\x09\x09\x36\x4c\x3f\x30\x6e\x08\x08\x00\x05\x88\x96\x0d\x73\xd7\x19\x01\x03\xf5\xb6\x1b";

    #[test]
    fn test_varint_round_trip() {
        let test_values = vec![0, 127, 128, 16384];

        for val in test_values {
            let mut buf = Vec::new();
            let mut ser = Serializer::new(&mut buf);
            ser.write_uint(val).unwrap();

            let mut deser = Deserializer::new(&buf[..]);
            let result = deser.read_uint().unwrap();
            assert_eq!(result, val, "Round-trip failed for value {}", val);
        }
    }

    #[test]
    fn test_bad_magic() {
        let bad_magic = b"\x00WrongMagic\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let mut deser = Deserializer::new(&bad_magic[..]);
        let result = deser.read_magic();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::BadMagic(_)));
    }

    #[test]
    fn test_magic_ok() {
        let mut deser = Deserializer::new(MAGIC);
        assert!(deser.read_magic().is_ok());
    }

    #[test]
    fn test_version_ok() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(VERSION).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        assert!(deser.read_version().is_ok());
    }

    #[test]
    fn test_bad_version() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(99).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = deser.read_version();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::BadVersion(99)));
    }

    #[test]
    fn test_read_bytes_length_validation() {
        // Test that read_bytes validates length properly
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(50).unwrap(); // Length of 50
        ser.write_fixed_bytes(&[0u8; 50]).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        // Should fail because 50 is out of range [1, 10]
        let result = deser.read_bytes(1, 10);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::BadLength { min: 1, max: 10, val: 50 }));
    }

    #[test]
    fn test_small_round_trip() {
        let mut rt1 = vec![];

        let ots = DetachedTimestampFile::from_reader(SMALL_TEST);
        assert!(ots.is_ok(), "Failed to deserialize SMALL_TEST");
        let ots = ots.unwrap();
        assert!(ots.to_writer(&mut rt1).is_ok(), "Failed to serialize SMALL_TEST");
        assert_eq!(rt1, SMALL_TEST, "SMALL_TEST round-trip mismatch");
    }

    #[test]
    fn test_large_round_trip() {
        let mut rt2 = vec![];

        let ots = DetachedTimestampFile::from_reader(LARGE_TEST);
        assert!(ots.is_ok(), "Failed to deserialize LARGE_TEST");
        let ots = ots.unwrap();
        assert!(ots.to_writer(&mut rt2).is_ok(), "Failed to serialize LARGE_TEST");
        assert_eq!(rt2, LARGE_TEST, "LARGE_TEST round-trip mismatch");
    }

    #[test]
    fn test_check_eof_with_trailing_bytes() {
        let data = b"extra data";
        let mut deser = Deserializer::new(&data[..]);
        let result = deser.check_eof();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::TrailingBytes));
    }

    #[test]
    fn test_check_eof_empty() {
        let data = b"";
        let mut deser = Deserializer::new(&data[..]);
        let result = deser.check_eof();
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserializer_into_inner() {
        let data = b"test data";
        let deser = Deserializer::new(&data[..]);
        let _reader = deser.into_inner();
        // Just verify it returns without panic
    }

    #[test]
    fn test_serializer_into_inner() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_byte(0x42).unwrap();
        let writer = ser.into_inner();
        assert_eq!(*writer, vec![0x42]);
    }

    #[test]
    fn test_write_uint_large_values() {
        // Test various large values
        let test_values = vec![127, 128, 255, 256, 16383, 16384, 65535, 65536];

        for val in test_values {
            let mut buf = Vec::new();
            let mut ser = Serializer::new(&mut buf);
            ser.write_uint(val).unwrap();

            let mut deser = Deserializer::new(&buf[..]);
            let result = deser.read_uint().unwrap();
            assert_eq!(result, val, "Failed round-trip for value {}", val);
        }
    }

    #[test]
    fn test_write_uint_zero() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(0).unwrap();
        assert_eq!(buf, vec![0x00]);

        let mut deser = Deserializer::new(&buf[..]);
        assert_eq!(deser.read_uint().unwrap(), 0);
    }

    #[test]
    fn test_read_fixed_bytes_empty() {
        let data = b"";
        let mut deser = Deserializer::new(&data[..]);
        let result = deser.read_fixed_bytes(0).unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_write_fixed_bytes_empty() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_fixed_bytes(&[]).unwrap();
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_read_bytes_in_range() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(5).unwrap();
        ser.write_fixed_bytes(&[1, 2, 3, 4, 5]).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = deser.read_bytes(1, 10).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_read_bytes_below_min() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(5).unwrap();
        ser.write_fixed_bytes(&[1, 2, 3, 4, 5]).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = deser.read_bytes(10, 20);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::BadLength { min: 10, max: 20, val: 5 }));
    }

    #[test]
    fn test_detached_timestamp_display() {
        use crate::ots::digest::DigestType;
        use crate::ots::timestamp::*;

        let file = DetachedTimestampFile {
            digest_type: DigestType::Sha256,
            timestamp: Timestamp {
                start_digest: vec![0xaa, 0xbb],
                first_step: Step {
                    data: StepData::Attestation(crate::ots::attestation::Attestation::Bitcoin {
                        height: 100,
                    }),
                    output: vec![0xaa, 0xbb],
                    next: vec![],
                },
            },
        };

        let display = format!("{}", file);
        assert!(display.contains("SHA256 digest"));
        assert!(display.contains("Starting digest: aabb"));
    }

    #[test]
    fn test_detached_timestamp_clone() {
        use crate::ots::digest::DigestType;
        use crate::ots::timestamp::*;

        let file1 = DetachedTimestampFile {
            digest_type: DigestType::Sha256,
            timestamp: Timestamp {
                start_digest: vec![0x01],
                first_step: Step {
                    data: StepData::Attestation(crate::ots::attestation::Attestation::Bitcoin {
                        height: 42,
                    }),
                    output: vec![0x01],
                    next: vec![],
                },
            },
        };

        let file2 = file1.clone();
        assert_eq!(file1, file2);
    }

    #[test]
    fn test_from_reader_with_trailing_bytes() {
        // Create a valid OTS file with extra bytes at the end
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_magic().unwrap();
        ser.write_version().unwrap();
        ser.write_byte(0x08).unwrap(); // SHA256
        ser.write_fixed_bytes(&[0xaa; 32]).unwrap(); // 32-byte digest
                                                     // Add simple attestation
        ser.write_byte(0x00).unwrap(); // Attestation tag
        ser.write_fixed_bytes(crate::ots::attestation::BITCOIN_TAG).unwrap();
        let mut inner = Vec::new();
        let mut inner_ser = Serializer::new(&mut inner);
        inner_ser.write_uint(100).unwrap();
        ser.write_bytes(inner_ser.into_inner()).unwrap();
        // Add trailing bytes
        ser.write_byte(0xff).unwrap();

        let result = DetachedTimestampFile::from_reader(&buf[..]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::TrailingBytes));
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAGIC.len(), 31);
        assert_eq!(VERSION, 1);
    }
}
