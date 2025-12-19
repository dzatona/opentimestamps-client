use clap::Parser;

mod cli;
mod error;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> error::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    if cli.verbose {
        log::info!("Verbose mode enabled");
    }

    match cli.command {
        Command::Stamp { files, .. } => {
            println!("TODO: stamp {files:?}");
        }
        Command::Verify { file, .. } => {
            println!("TODO: verify {}", file.display());
        }
        Command::Upgrade { file, .. } => {
            println!("TODO: upgrade {}", file.display());
        }
        Command::Info { file, .. } => {
            println!("TODO: info {}", file.display());
        }
    }

    Ok(())
}
