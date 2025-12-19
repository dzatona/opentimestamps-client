use crate::calendar::CalendarClient;
use crate::error::{Error, Result};
use crate::ots::{Attestation, Deserializer, DetachedTimestampFile, Step, StepData, Timestamp};
use log::{debug, info, warn};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor};
use std::path::Path;
use std::time::Duration;

/// Execute the upgrade command
///
/// Reads an existing .ots file, finds pending attestations, queries calendar
/// servers for completed Bitcoin attestations, and merges them into the timestamp.
///
/// # Arguments
///
/// * `file` - Path to the .ots file to upgrade
/// * `dry_run` - If true, don't save changes (just check availability)
///
/// # Errors
///
/// Returns error if:
/// - File cannot be read or parsed
/// - Backup fails
/// - Updated file cannot be written
pub async fn execute(file: &Path, dry_run: bool) -> Result<()> {
    info!("Upgrading timestamp: {}", file.display());

    // 1. Read .ots file
    let f = File::open(file)?;
    let reader = BufReader::new(f);
    let mut ots = DetachedTimestampFile::from_reader(reader)?;

    // 2. Find pending attestations and try to upgrade
    let client = CalendarClient::new(Duration::from_secs(30))?;
    let upgraded = upgrade_timestamp(&mut ots.timestamp, &client).await?;

    if !upgraded {
        info!("Timestamp not yet ready for upgrade (still pending)");
        return Ok(());
    }

    if dry_run {
        info!("Dry run - not saving changes");
        return Ok(());
    }

    // 3. Backup original
    let backup_path = format!("{}.bak", file.display());
    if Path::new(&backup_path).exists() {
        warn!("Backup file {backup_path} already exists, skipping backup");
    } else {
        fs::copy(file, &backup_path)?;
        debug!("Backed up to {backup_path}");
    }

    // 4. Save updated .ots
    let f = File::create(file)?;
    let mut writer = BufWriter::new(f);
    ots.to_writer(&mut writer)?;

    info!("Timestamp upgraded successfully");
    Ok(())
}

/// Recursively upgrade a timestamp by finding and replacing pending attestations
///
/// Walks the timestamp tree looking for `PendingAttestation` nodes, queries the
/// calendar server for the completed timestamp, and merges the result.
///
/// Returns true if any attestations were upgraded.
async fn upgrade_timestamp(timestamp: &mut Timestamp, client: &CalendarClient) -> Result<bool> {
    upgrade_step(&mut timestamp.first_step, client).await
}

/// Recursively upgrade a single step in the timestamp tree
///
/// Handles three cases:
/// - Attestation: If pending, try to fetch completed version from calendar
/// - Fork: Process all branches
/// - Op: Process next steps
///
/// Returns true if any attestations were upgraded in this step or its children.
#[async_recursion::async_recursion]
async fn upgrade_step(step: &mut Step, client: &CalendarClient) -> Result<bool> {
    let mut upgraded = false;

    match &step.data {
        StepData::Attestation(Attestation::Pending { uri }) => {
            info!("Found pending attestation at {uri}");

            // Try to get completed timestamp from calendar
            match client.get_timestamp(uri, &step.output).await {
                Ok(Some(response)) => {
                    // Parse the response into a timestamp
                    match parse_calendar_response(&step.output, &response) {
                        Ok(new_timestamp) => {
                            // Merge the new timestamp steps into this step's next chain
                            // The calendar returns a timestamp that should contain Bitcoin attestation
                            debug!(
                                "Merging {} new steps from calendar",
                                count_steps(&new_timestamp.first_step)
                            );

                            // Replace this attestation node with the new timestamp chain
                            step.data = new_timestamp.first_step.data.clone();
                            step.next.clone_from(&new_timestamp.first_step.next);

                            info!("Upgraded pending attestation");
                            upgraded = true;
                        }
                        Err(e) => {
                            warn!("Failed to parse calendar response: {e}");
                        }
                    }
                }
                Ok(None) => {
                    debug!("Attestation not yet available at {uri}");
                }
                Err(e) => {
                    warn!("Failed to query calendar {uri}: {e}");
                }
            }
        }
        StepData::Fork => {
            // Process all branches in a fork
            for next_step in &mut step.next {
                let branch_upgraded = upgrade_step(next_step, client).await?;
                upgraded |= branch_upgraded;
            }
        }
        StepData::Op(_) => {
            // Process all next steps after an operation
            for next_step in &mut step.next {
                let branch_upgraded = upgrade_step(next_step, client).await?;
                upgraded |= branch_upgraded;
            }
        }
        // Bitcoin attestations and unknown attestations are already complete
        StepData::Attestation(Attestation::Bitcoin { .. } | Attestation::Unknown { .. }) => {}
    }

    Ok(upgraded)
}

/// Parse calendar server response into a Timestamp
///
/// The calendar returns binary timestamp data that needs to be deserialized
/// using the opentimestamps library.
fn parse_calendar_response(commitment: &[u8], response: &[u8]) -> Result<Timestamp> {
    let cursor = Cursor::new(response);
    let mut deserializer = Deserializer::new(cursor);

    Timestamp::deserialize(&mut deserializer, commitment.to_vec()).map_err(Error::InvalidOts)
}

/// Count the number of steps in a timestamp (for debugging)
fn count_steps(step: &Step) -> usize {
    1 + step.next.iter().map(count_steps).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ots::Op;

    #[test]
    fn test_count_steps() {
        let step = Step { data: StepData::Op(Op::Sha256), output: vec![0u8; 32], next: vec![] };

        assert_eq!(count_steps(&step), 1);

        let step_with_next = Step {
            data: StepData::Op(Op::Sha256),
            output: vec![0u8; 32],
            next: vec![Step {
                data: StepData::Op(Op::Sha256),
                output: vec![0u8; 32],
                next: vec![],
            }],
        };

        assert_eq!(count_steps(&step_with_next), 2);
    }

    #[test]
    fn test_parse_calendar_response_invalid() {
        let commitment = vec![0u8; 32];
        let invalid_response = vec![0xff, 0xff];

        let result = parse_calendar_response(&commitment, &invalid_response);
        assert!(result.is_err());
    }
}
