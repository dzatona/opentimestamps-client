#![allow(clippy::multiple_crate_versions)]

use clap::Parser;

mod calendar;
mod cli;
mod commands;
mod error;
mod ots;
mod verifier;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> error::Result<()> {
    let cli = Cli::parse();

    // Initialize logger based on verbose flag
    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }

    match cli.command {
        Command::Stamp { files, calendar, timeout } => {
            commands::stamp::execute(&files, calendar, timeout).await?;
        }
        Command::Verify { file, target } => {
            commands::verify::execute(&file, target.as_deref()).await?;
        }
        Command::Upgrade { file, dry_run } => {
            commands::upgrade::execute(&file, dry_run).await?;
        }
        Command::Info { file, detailed } => {
            commands::info::execute(&file, detailed)?;
        }
    }

    Ok(())
}
