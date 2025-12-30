//! Timestamp structures and display formatting
//!
//! A timestamp represents a proof that some data existed at a specific time.

use std::fmt;
use std::io::{Read, Write};

use super::attestation::Attestation;
use super::error::{OtsError, Result, RECURSION_LIMIT};
use super::op::Op;
use super::ser::{Deserializer, Serializer};

/// The actual contents of an execution step
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StepData {
    /// This step splits execution into multiple paths
    Fork,
    /// This step executes some concrete operation
    Op(Op),
    /// This step asserts an attestation of the current state by some timestamp service
    Attestation(Attestation),
}

/// An execution step in a timestamp verification
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step {
    /// The contents of the step
    pub data: StepData,
    /// The output after execution
    pub output: Vec<u8>,
    /// A list of steps to execute after this one
    pub next: Vec<Step>,
}

/// Main structure representing a timestamp
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Timestamp {
    /// The starting document digest
    pub start_digest: Vec<u8>,
    /// The first execution step in verifying it
    pub first_step: Step,
}

impl Timestamp {
    /// Deserialize one step in a timestamp
    fn deserialize_step_recurse<R: Read>(
        deser: &mut Deserializer<R>,
        input_digest: Vec<u8>,
        tag: Option<u8>,
        recursion_limit: usize,
    ) -> Result<Step> {
        if recursion_limit == 0 {
            return Err(OtsError::StackOverflow);
        }

        // Read next tag if we weren't given one
        let tag = match tag {
            Some(tag) => tag,
            None => deser.read_byte()?,
        };

        // A tag typically indicates an op to execute, but the two special values
        // 0xff (fork) and 0x00 (read attestation and terminate path) are used to
        // provide multiple attestations
        match tag {
            // Attestation
            0x00 => {
                let attest = Attestation::deserialize(deser)?;
                Ok(Step { data: StepData::Attestation(attest), output: input_digest, next: vec![] })
            }
            // Fork
            0xff => {
                let mut forks = vec![];
                let mut next_tag = 0xff;
                while next_tag == 0xff {
                    forks.push(Self::deserialize_step_recurse(
                        deser,
                        input_digest.clone(),
                        None,
                        recursion_limit - 1,
                    )?);
                    next_tag = deser.read_byte()?;
                }
                forks.push(Self::deserialize_step_recurse(
                    deser,
                    input_digest.clone(),
                    Some(next_tag),
                    recursion_limit - 1,
                )?);
                Ok(Step { data: StepData::Fork, output: input_digest, next: forks })
            }
            // An actual op tag
            tag => {
                // parse tag
                let op = Op::deserialize_with_tag(deser, tag)?;
                let output_digest = op.execute(&input_digest);
                // recurse
                let next = vec![Self::deserialize_step_recurse(
                    deser,
                    output_digest.clone(),
                    None,
                    recursion_limit - 1,
                )?];
                Ok(Step { data: StepData::Op(op), output: output_digest, next })
            }
        }
    }

    /// Deserialize a timestamp
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The recursion limit is exceeded
    /// - Deserialization of any component fails
    pub fn deserialize<R: Read>(deser: &mut Deserializer<R>, digest: Vec<u8>) -> Result<Self> {
        let first_step =
            Self::deserialize_step_recurse(deser, digest.clone(), None, RECURSION_LIMIT)?;

        Ok(Self { start_digest: digest, first_step })
    }

    /// Serialize one step in a timestamp recursively
    fn serialize_step_recurse<W: Write>(ser: &mut Serializer<W>, step: &Step) -> Result<()> {
        match step.data {
            StepData::Fork => {
                for i in 0..step.next.len() - 1 {
                    ser.write_byte(0xff)?;
                    Self::serialize_step_recurse(ser, &step.next[i])?;
                }
                Self::serialize_step_recurse(ser, &step.next[step.next.len() - 1])
            }
            StepData::Op(ref op) => {
                op.serialize(ser)?;
                Self::serialize_step_recurse(ser, &step.next[0])
            }
            StepData::Attestation(ref attest) => {
                ser.write_byte(0x00)?;
                attest.serialize(ser)
            }
        }
    }

    /// Serialize a timestamp
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn serialize<W: Write>(&self, ser: &mut Serializer<W>) -> Result<()> {
        Self::serialize_step_recurse(ser, &self.first_step)
    }
}

/// Recursively format a step and its children
fn fmt_recurse(
    step: &Step,
    f: &mut fmt::Formatter<'_>,
    depth: usize,
    first_line: bool,
) -> fmt::Result {
    /// Write indentation for the current depth
    fn indent(f: &mut fmt::Formatter<'_>, depth: usize, first_line: bool) -> fmt::Result {
        if depth == 0 {
            return Ok(());
        }

        for _ in 0..depth - 1 {
            f.write_str("    ")?;
        }
        if first_line {
            f.write_str("--->")?;
        } else {
            f.write_str("    ")?;
        }
        Ok(())
    }

    match &step.data {
        StepData::Fork => {
            indent(f, depth, first_line)?;
            writeln!(f, "(fork {} ways)", step.next.len())?;
            for fork in &step.next {
                fmt_recurse(fork, f, depth + 1, true)?;
            }
            Ok(())
        }
        StepData::Op(op) => {
            indent(f, depth, first_line)?;
            writeln!(f, "execute {}", op)?;
            indent(f, depth, false)?;
            writeln!(f, " result {}", hex::encode(&step.output))?;
            fmt_recurse(&step.next[0], f, depth, false)
        }
        StepData::Attestation(attest) => {
            indent(f, depth, first_line)?;
            writeln!(f, "result attested by {}", attest)
        }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Starting digest: {}", hex::encode(&self.start_digest))?;
        fmt_recurse(&self.first_step, f, 0, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_data_variants() {
        let fork = StepData::Fork;
        let op = StepData::Op(Op::Sha256);
        let attestation = StepData::Attestation(Attestation::Bitcoin { height: 123 });

        assert!(matches!(fork, StepData::Fork));
        assert!(matches!(op, StepData::Op(_)));
        assert!(matches!(attestation, StepData::Attestation(_)));
    }

    #[test]
    fn test_step_clone_and_equality() {
        let step1 = Step { data: StepData::Op(Op::Sha256), output: vec![1, 2, 3], next: vec![] };
        let step2 = step1.clone();
        assert_eq!(step1, step2);
    }

    #[test]
    fn test_timestamp_display_simple() {
        let timestamp = Timestamp {
            start_digest: vec![0xaa, 0xbb, 0xcc],
            first_step: Step {
                data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
                output: vec![0xaa, 0xbb, 0xcc],
                next: vec![],
            },
        };

        let display = format!("{}", timestamp);
        assert!(display.contains("Starting digest: aabbcc"));
        assert!(display.contains("Bitcoin block 100"));
    }

    #[test]
    fn test_timestamp_display_with_op() {
        let timestamp = Timestamp {
            start_digest: vec![0x00, 0x01],
            first_step: Step {
                data: StepData::Op(Op::Sha256),
                output: vec![0x02, 0x03],
                next: vec![Step {
                    data: StepData::Attestation(Attestation::Bitcoin { height: 200 }),
                    output: vec![0x02, 0x03],
                    next: vec![],
                }],
            },
        };

        let display = format!("{}", timestamp);
        assert!(display.contains("Starting digest: 0001"));
        assert!(display.contains("execute SHA256()"));
        assert!(display.contains("result 0203"));
        assert!(display.contains("Bitcoin block 200"));
    }

    #[test]
    fn test_timestamp_display_with_fork() {
        let timestamp = Timestamp {
            start_digest: vec![0xff],
            first_step: Step {
                data: StepData::Fork,
                output: vec![0xff],
                next: vec![
                    Step {
                        data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
                        output: vec![0xff],
                        next: vec![],
                    },
                    Step {
                        data: StepData::Attestation(Attestation::Bitcoin { height: 200 }),
                        output: vec![0xff],
                        next: vec![],
                    },
                ],
            },
        };

        let display = format!("{}", timestamp);
        assert!(display.contains("(fork 2 ways)"));
        assert!(display.contains("Bitcoin block 100"));
        assert!(display.contains("Bitcoin block 200"));
    }

    #[test]
    fn test_serialize_deserialize_simple_timestamp() {
        use crate::ots::ser::*;

        let timestamp = Timestamp {
            start_digest: vec![0xaa, 0xbb, 0xcc],
            first_step: Step {
                data: StepData::Attestation(Attestation::Bitcoin { height: 12345 }),
                output: vec![0xaa, 0xbb, 0xcc],
                next: vec![],
            },
        };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Timestamp::deserialize(&mut deser, vec![0xaa, 0xbb, 0xcc]).unwrap();
        assert_eq!(timestamp, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_timestamp_with_op() {
        use crate::ots::op::Op;
        use crate::ots::ser::*;

        let input_digest = vec![0x01, 0x02];
        let op = Op::Sha256;
        let output_digest = op.execute(&input_digest);

        let timestamp = Timestamp {
            start_digest: input_digest.clone(),
            first_step: Step {
                data: StepData::Op(op.clone()),
                output: output_digest.clone(),
                next: vec![Step {
                    data: StepData::Attestation(Attestation::Bitcoin { height: 500 }),
                    output: output_digest.clone(),
                    next: vec![],
                }],
            },
        };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Timestamp::deserialize(&mut deser, input_digest).unwrap();
        assert_eq!(timestamp, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_timestamp_with_fork() {
        use crate::ots::ser::*;

        let digest = vec![0xff];
        let timestamp = Timestamp {
            start_digest: digest.clone(),
            first_step: Step {
                data: StepData::Fork,
                output: digest.clone(),
                next: vec![
                    Step {
                        data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
                        output: digest.clone(),
                        next: vec![],
                    },
                    Step {
                        data: StepData::Attestation(Attestation::Pending {
                            uri: "https://example.com".to_string(),
                        }),
                        output: digest.clone(),
                        next: vec![],
                    },
                ],
            },
        };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Timestamp::deserialize(&mut deser, digest.clone()).unwrap();
        assert_eq!(timestamp, deserialized);
    }

    #[test]
    fn test_deserialize_stack_overflow() {
        use crate::ots::error::RECURSION_LIMIT;
        use crate::ots::op::Op;
        use crate::ots::ser::*;

        // Create a deeply nested timestamp that exceeds recursion limit
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);

        // Write more operations than the recursion limit allows
        for _ in 0..=RECURSION_LIMIT {
            ser.write_byte(Op::Sha256.tag()).unwrap();
        }
        // Terminate with an attestation
        ser.write_byte(0x00).unwrap();
        ser.write_fixed_bytes(crate::ots::attestation::BITCOIN_TAG).unwrap();
        let mut inner = Vec::new();
        let mut inner_ser = Serializer::new(&mut inner);
        inner_ser.write_uint(100).unwrap();
        ser.write_bytes(inner_ser.into_inner()).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = Timestamp::deserialize(&mut deser, vec![0x00]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::StackOverflow));
    }

    #[test]
    fn test_serialize_fork_with_multiple_branches() {
        use crate::ots::ser::*;

        let digest = vec![0xaa];
        let timestamp = Timestamp {
            start_digest: digest.clone(),
            first_step: Step {
                data: StepData::Fork,
                output: digest.clone(),
                next: vec![
                    Step {
                        data: StepData::Attestation(Attestation::Bitcoin { height: 1 }),
                        output: digest.clone(),
                        next: vec![],
                    },
                    Step {
                        data: StepData::Attestation(Attestation::Bitcoin { height: 2 }),
                        output: digest.clone(),
                        next: vec![],
                    },
                    Step {
                        data: StepData::Attestation(Attestation::Bitcoin { height: 3 }),
                        output: digest.clone(),
                        next: vec![],
                    },
                ],
            },
        };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let deserialized = Timestamp::deserialize(&mut deser, digest.clone()).unwrap();
        assert_eq!(timestamp, deserialized);
    }

    #[test]
    fn test_timestamp_clone() {
        let timestamp = Timestamp {
            start_digest: vec![0x01],
            first_step: Step {
                data: StepData::Attestation(Attestation::Bitcoin { height: 42 }),
                output: vec![0x01],
                next: vec![],
            },
        };

        let cloned = timestamp.clone();
        assert_eq!(timestamp, cloned);
    }

    #[test]
    fn test_step_data_debug() {
        use crate::ots::op::Op;

        let fork = StepData::Fork;
        let op = StepData::Op(Op::Sha256);
        let attestation = StepData::Attestation(Attestation::Bitcoin { height: 100 });

        // Just ensure Debug is implemented correctly
        assert!(format!("{:?}", fork).contains("Fork"));
        assert!(format!("{:?}", op).contains("Op"));
        assert!(format!("{:?}", attestation).contains("Attestation"));
    }
}
