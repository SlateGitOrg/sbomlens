//! `sbomlens` binary: argument parsing, logging and exit codes.
//!
//! Exit codes: 0 success, 1 `--fail-on` threshold reached, 2 error.

use std::process::ExitCode;

use clap::Parser;
use sbomlens::cli::{run, Cli, Outcome};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let default = match cli.verbose {
        0 => "warn",
        1 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_env("SBOMLENS_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    match run(&cli, &mut lock) {
        Ok(Outcome::Ok) => ExitCode::SUCCESS,
        Ok(Outcome::PolicyFailed) => ExitCode::from(1),
        Err(e) => {
            eprintln!("sbomlens: error: {e}");
            ExitCode::from(2)
        }
    }
}
