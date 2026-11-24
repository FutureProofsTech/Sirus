//! Sirus protector command line.

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::float_arithmetic,
    clippy::missing_inline_in_public_items,
    clippy::exhaustive_structs
)]
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::large_stack_arrays,
        clippy::large_stack_frames,
        reason = "unit tests use assertion panics and fixed parser fixtures"
    )
)]

mod cli;
mod entropy;
mod error;
mod pipeline;
mod vmgen;

use std::io::Write as _;
use std::process::ExitCode;

use error::{ProtectError, Result};

fn main() -> ExitCode {
    let worker = std::thread::Builder::new()
        .name("sirus".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(run);
    let joined = match worker {
        Ok(handle) => handle.join(),
        Err(error) => {
            let mut stderr = std::io::stderr().lock();
            drop(writeln!(stderr, "sirus: failed to start worker: {error}"));
            return ExitCode::from(1);
        }
    };
    match joined {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(error)) => report_error(&error),
        Err(_) => {
            let mut stderr = std::io::stderr().lock();
            drop(writeln!(stderr, "sirus: worker thread panicked"));
            ExitCode::from(1)
        }
    }
}

fn report_error(error: &ProtectError) -> ExitCode {
    let mut stderr = std::io::stderr().lock();
    drop(writeln!(stderr, "sirus: {error}"));
    if matches!(error, &ProtectError::Usage(_)) {
        ExitCode::from(2)
    } else {
        ExitCode::from(1)
    }
}

fn run() -> Result<()> {
    let action = cli::parse()?;
    let mut stdout = std::io::stdout().lock();
    run_with_writer(action, &mut stdout)
}

fn run_with_writer(action: cli::Action, output: &mut impl std::io::Write) -> Result<()> {
    match action {
        cli::Action::Help => {
            write!(output, "{}", cli::help_text())
                .map_err(|error| ProtectError::io("write help", &error))?;
            Ok(())
        }
        cli::Action::Version => {
            writeln!(output, "sirus {}", env!("CARGO_PKG_VERSION"))
                .map_err(|error| ProtectError::io("write version", &error))?;
            Ok(())
        }
        cli::Action::Inspect(path) => pipeline::inspect(&path, output),
        cli::Action::HardenCheck => pipeline::harden_check(output),
        cli::Action::Protect(arguments) => {
            let report = pipeline::protect(&arguments)?;
            pipeline::print_report(&report, output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run_with_writer;
    use crate::cli::Action;
    use crate::error::ProtectError;

    #[test]
    fn help_and_version_write_output() {
        let mut output = Vec::new();
        assert!(run_with_writer(Action::Help, &mut output).is_ok());
        assert_ne!(output.len(), 0);
        let mut output = Vec::new();
        assert!(run_with_writer(Action::Version, &mut output).is_ok());
        assert!(String::from_utf8_lossy(&output).contains("sirus"));
    }

    #[test]
    fn inspect_failure_is_propagated() {
        let mut output = Vec::new();
        let result = run_with_writer(Action::Inspect("definitely-missing".into()), &mut output);
        assert!(matches!(result, Err(ProtectError::Io(_))));
    }
}
