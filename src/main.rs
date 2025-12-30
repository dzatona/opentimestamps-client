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
    env_logger::init();

    let cli = Cli::parse();

    if cli.verbose {
        log::info!("Verbose mode enabled");
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
