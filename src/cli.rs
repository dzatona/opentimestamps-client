use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// `OpenTimestamps` command-line interface
#[derive(Parser)]
#[command(name = "ots")]
#[command(about = "OpenTimestamps client", long_about = None)]
#[command(version)]
pub struct Cli {
    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Available commands
#[derive(Subcommand)]
pub enum Command {
    /// Create timestamp for file(s)
    Stamp {
        /// Files to timestamp
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Calendar server URLs (can specify multiple)
        #[arg(short, long)]
        calendar: Option<Vec<String>>,

        /// Timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Verify a timestamp
    Verify {
        /// OTS file to verify
        file: PathBuf,

        /// Original file (optional, derived from .ots filename if not provided)
        #[arg(short, long)]
        target: Option<PathBuf>,
    },

    /// Upgrade pending timestamp to Bitcoin attestation
    Upgrade {
        /// OTS file to upgrade
        file: PathBuf,

        /// Dry run, don't modify file
        #[arg(short, long)]
        dry_run: bool,
    },

    /// Show timestamp information
    Info {
        /// OTS file to inspect
        file: PathBuf,

        /// Show detailed output
        #[arg(short, long)]
        detailed: bool,
    },
}
