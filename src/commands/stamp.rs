use crate::calendar::CalendarClient;
use crate::error::Result;
use log::{debug, info};
use opentimestamps::op::Op;
use opentimestamps::ser::{Deserializer, DigestType};
use opentimestamps::timestamp::{Step, StepData, Timestamp};
use opentimestamps::DetachedTimestampFile;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::path::Path;
use std::time::Duration;

/// Execute the stamp command
///
/// Creates timestamps for one or more files by:
/// 1. Computing SHA256 hash of each file
/// 2. Adding a random 16-byte nonce for privacy
/// 3. Computing SHA256 of (file_hash + nonce)
/// 4. Submitting the commitment to calendar servers
/// 5. Parsing the calendar response into a Timestamp
/// 6. Building the complete timestamp chain
/// 7. Saving the .ots file
///
/// # Arguments
///
/// * `files` - List of file paths to timestamp
/// * `calendar_urls` - Optional list of calendar server URLs (uses defaults if None)
/// * `timeout` - Timeout in seconds for HTTP requests
///
/// # Errors
///
/// Returns error if:
/// - File cannot be read
/// - Calendar submission fails
/// - .ots file cannot be written
pub async fn execute(
    files: &[impl AsRef<Path>],
    calendar_urls: Option<Vec<String>>,
    timeout: u64,
) -> Result<()> {
    let client = CalendarClient::new(Duration::from_secs(timeout))?;

    // Use provided URLs or empty vec (client will use defaults)
    let calendar_urls_ref: Vec<String> = calendar_urls.unwrap_or_default();

    for file_path in files {
        let path = file_path.as_ref();
        info!("Stamping file: {}", path.display());

        // 1. Read file and compute SHA256
        let file_digest = hash_file(path)?;
        debug!("File digest: {}", hex::encode(file_digest));

        // 2. Add nonce for privacy (16 random bytes)
        let nonce: [u8; 16] = rand::random();
        debug!("Nonce: {}", hex::encode(nonce));

        // 3. Compute commitment: SHA256(file_digest || nonce)
        let mut hasher = Sha256::new();
        hasher.update(file_digest);
        hasher.update(nonce);
        let commitment: [u8; 32] = hasher.finalize().into();
        debug!("Commitment: {}", hex::encode(commitment));

        // 4. Submit to calendars
        let response = client
            .submit_to_calendars(&calendar_urls_ref, &commitment)
            .await?;

        // 5. Parse calendar response into Timestamp
        let calendar_timestamp = parse_calendar_response(&commitment, &response)?;

        // 6. Build full timestamp structure
        // Structure: file_digest -> append(nonce) -> sha256 -> calendar_timestamp
        let timestamp = build_timestamp(file_digest.to_vec(), nonce.to_vec(), calendar_timestamp);

        // 7. Create DetachedTimestampFile
        let ots = DetachedTimestampFile {
            digest_type: DigestType::Sha256,
            timestamp,
        };

        // 8. Save .ots file
        let ots_path = format!("{}.ots", path.display());
        save_ots(&ots, &ots_path)?;

        info!("Created timestamp: {}", ots_path);
    }

    Ok(())
}

/// Hash a file using SHA256
///
/// Reads the file in chunks to handle large files efficiently.
fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().into())
}

/// Parse calendar server response into a Timestamp
///
/// The calendar returns binary timestamp data that needs to be deserialized
/// using the opentimestamps library.
fn parse_calendar_response(commitment: &[u8], response: &[u8]) -> Result<Timestamp> {
    let cursor = Cursor::new(response);
    let mut deserializer = Deserializer::new(cursor);

    Timestamp::deserialize(&mut deserializer, commitment.to_vec())
        .map_err(crate::error::Error::InvalidOts)
}

/// Build the complete timestamp structure
///
/// Creates the chain: file_digest -> append(nonce) -> sha256 -> calendar_timestamp
///
/// The structure represents:
/// 1. Start with file digest
/// 2. Append nonce operation
/// 3. SHA256 hash operation
/// 4. Calendar timestamp (contains attestations)
fn build_timestamp(
    file_digest: Vec<u8>,
    nonce: Vec<u8>,
    calendar_timestamp: Timestamp,
) -> Timestamp {
    // Calculate intermediate value: file_digest || nonce
    let mut appended = file_digest.clone();
    appended.extend_from_slice(&nonce);

    // The commitment should match calendar_timestamp's start_digest
    let commitment = Sha256::digest(&appended).to_vec();

    // Build the chain:
    // Step 1: Append nonce
    let append_step = Step {
        data: StepData::Op(Op::Append(nonce)),
        output: appended,
        next: vec![Step {
            // Step 2: SHA256 hash
            data: StepData::Op(Op::Sha256),
            output: commitment.clone(),
            // Step 3: Calendar timestamp (contains the actual attestations)
            next: vec![calendar_timestamp.first_step],
        }],
    };

    Timestamp {
        start_digest: file_digest,
        first_step: append_step,
    }
}

/// Save a DetachedTimestampFile to disk
///
/// Uses the opentimestamps library's serialization to write the .ots file.
fn save_ots(ots: &DetachedTimestampFile, path: &str) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    ots.to_writer(&mut writer)?;
    writer.flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_file() {
        // Create a temporary file
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_stamp.txt");

        std::fs::write(&test_file, b"Hello, OpenTimestamps!").unwrap();

        let hash = hash_file(&test_file).unwrap();

        // Verify it's a valid 32-byte hash
        assert_eq!(hash.len(), 32);

        // Clean up
        std::fs::remove_file(&test_file).unwrap();
    }

    #[test]
    fn test_build_timestamp_structure() {
        let file_digest = vec![1u8; 32];
        let nonce = vec![2u8; 16];

        // Create a minimal calendar timestamp for testing
        let calendar_timestamp = Timestamp {
            start_digest: vec![0u8; 32], // This should be the commitment
            first_step: Step {
                data: StepData::Op(Op::Sha256),
                output: vec![0u8; 32],
                next: vec![],
            },
        };

        let timestamp = build_timestamp(file_digest.clone(), nonce.clone(), calendar_timestamp);

        // Verify structure
        assert_eq!(timestamp.start_digest, file_digest);
        assert!(matches!(
            timestamp.first_step.data,
            StepData::Op(Op::Append(_))
        ));
    }
}
