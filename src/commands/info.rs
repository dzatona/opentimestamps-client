use crate::error::Result;
use opentimestamps::attestation::Attestation;
use opentimestamps::timestamp::{Step, StepData};
use opentimestamps::DetachedTimestampFile;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Recursively collect all attestations from the timestamp tree
fn collect_attestations(step: &Step, attestations: &mut Vec<Attestation>) {
    match &step.data {
        StepData::Attestation(att) => {
            attestations.push(att.clone());
        }
        StepData::Fork => {
            for next_step in &step.next {
                collect_attestations(next_step, attestations);
            }
        }
        StepData::Op(_) => {
            if !step.next.is_empty() {
                collect_attestations(&step.next[0], attestations);
            }
        }
    }
}

/// Execute the info command
///
/// Reads an OTS file and displays its timestamp information.
/// In normal mode, shows a summary (digest, attestations).
/// In detailed mode, prints the full structure using the Display trait.
pub fn execute(file: &Path, detailed: bool) -> Result<()> {
    let f = File::open(file)?;
    let reader = BufReader::new(f);

    let ots = DetachedTimestampFile::from_reader(reader)?;

    if detailed {
        // Print full details using Display trait
        println!("{ots}");
    } else {
        // Print summary
        println!("File: {}", file.display());
        println!("Digest type: {:?}", ots.digest_type);
        println!("Digest: {}", hex::encode(&ots.timestamp.start_digest));

        // Collect attestations
        let mut attestations = Vec::new();
        collect_attestations(&ots.timestamp.first_step, &mut attestations);

        println!("Attestations: {}", attestations.len());

        for att in &attestations {
            match att {
                Attestation::Bitcoin { height } => {
                    println!("  - Bitcoin block {height}");
                }
                Attestation::Pending { uri } => {
                    println!("  - Pending: {uri}");
                }
                Attestation::Unknown { tag, .. } => {
                    println!("  - Unknown (tag: {})", hex::encode(tag));
                }
            }
        }
    }

    Ok(())
}
