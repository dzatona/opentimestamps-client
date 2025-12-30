use crate::error::{Error, Result};
use crate::ots::{Attestation, DetachedTimestampFile, Step, StepData};
use crate::verifier::{BlockVerifier, ElectrumVerifier};
use log::{debug, info};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Execute verify command
///
/// Verifies an `OpenTimestamps` proof against the Bitcoin blockchain.
///
/// # Arguments
/// * `file` - Path to .ots timestamp file
/// * `target` - Optional path to original file. If None, derives from .ots filename
///
/// # Errors
/// Returns error if:
/// - File cannot be read
/// - Hash doesn't match
/// - No Bitcoin attestation found
/// - Blockchain verification fails
pub async fn execute(file: &Path, target: Option<&Path>) -> Result<()> {
    // 1. Read .ots file
    let f = File::open(file)?;
    let reader = BufReader::new(f);
    let ots = DetachedTimestampFile::from_reader(reader)?;

    // 2. Determine target file path
    let target_path = if let Some(p) = target {
        p.to_path_buf()
    } else {
        // Strip .ots extension to derive original filename
        let s = file.to_string_lossy();
        if let Some(stripped) = s.strip_suffix(".ots") {
            Path::new(stripped).to_path_buf()
        } else {
            return Err(Error::Verification(
                "Cannot determine target file: .ots extension missing".into(),
            ));
        }
    };

    if !target_path.exists() {
        return Err(Error::Verification(format!(
            "Target file does not exist: {}",
            target_path.display()
        )));
    }

    // 3. Hash target file and compare with timestamp
    let file_hash = hash_file(&target_path)?;
    if file_hash != ots.timestamp.start_digest.as_slice() {
        return Err(Error::Verification(format!(
            "File hash mismatch. Expected {}, got {}",
            hex::encode(&ots.timestamp.start_digest),
            hex::encode(&file_hash)
        )));
    }
    debug!("File hash matches: {}", hex::encode(&ots.timestamp.start_digest));

    // 4. Find Bitcoin attestation and verify against blockchain
    let verifier = ElectrumVerifier::new(None);

    if let Some((merkle_root, height)) = find_bitcoin_attestation(&ots.timestamp.first_step) {
        info!("Found Bitcoin attestation at block {height}");

        // Fetch block header from blockchain
        let header = verifier.get_block_header(height).await?;

        // Verify merkle root matches
        if merkle_root != header.merkle_root {
            return Err(Error::Verification(format!(
                "Merkle root mismatch at block {height}. Expected {}, got {}",
                hex::encode(merkle_root),
                hex::encode(header.merkle_root)
            )));
        }

        // Convert Unix timestamp to human-readable date
        let datetime = chrono::DateTime::from_timestamp(i64::from(header.time), 0).map_or_else(
            || "unknown".to_string(),
            |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        println!("Success! Bitcoin block {height} attests existence as of {datetime}");
        println!("Merkle root: {}", hex::encode(header.merkle_root));
        return Ok(());
    }

    Err(Error::NoBitcoinAttestation)
}

/// Hash file contents using SHA256
///
/// # Errors
/// Returns error if file cannot be read
fn hash_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

/// Recursively search timestamp tree for Bitcoin attestation
///
/// Returns tuple of (`merkle_root`, `block_height`) if found
#[allow(clippy::cast_possible_truncation)]
fn find_bitcoin_attestation(step: &Step) -> Option<([u8; 32], u32)> {
    if let StepData::Attestation(Attestation::Bitcoin { height }) = &step.data {
        // Found Bitcoin attestation - extract merkle root from step output
        if step.output.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&step.output[..32]);
            Some((arr, *height as u32))
        } else {
            None
        }
    } else {
        // Recursively search child steps
        for next in &step.next {
            if let Some(result) = find_bitcoin_attestation(next) {
                return Some(result);
            }
        }
        None
    }
}
