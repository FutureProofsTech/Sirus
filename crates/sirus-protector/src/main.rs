//! Sirus protector command line.

#![forbid(unsafe_code)]

mod cli;
mod entropy;
mod error;
mod pipeline;
mod vmgen;

use std::io::Write as _;
use std::process::ExitCode;

use error::{ProtectError, Result};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut stderr = std::io::stderr().lock();
            drop(writeln!(stderr, "sirus: {error}"));
            if let ProtectError::Usage(_) = error {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            }
        }
    }
}

fn run() -> Result<()> {
    let action = cli::parse()?;
    let mut stdout = std::io::stdout().lock();
    match action {
        cli::Action::Help => {
            write!(stdout, "{}", cli::help_text())
                .map_err(|error| ProtectError::io("write help", &error))?;
            Ok(())
        }
        cli::Action::Version => {
            writeln!(stdout, "sirus {}", env!("CARGO_PKG_VERSION"))
                .map_err(|error| ProtectError::io("write version", &error))?;
            Ok(())
        }
        cli::Action::Inspect(path) => pipeline::inspect(&path, &mut stdout),
        cli::Action::Protect(arguments) => {
            let report = pipeline::protect(&arguments)?;
            pipeline::print_report(&report, &mut stdout)
        }
    }
}
