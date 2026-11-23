//! Sirus protector command line.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    use std::io::Write as _;
    let mut stdout = std::io::stdout();
    drop(writeln!(stdout, "sirus: not yet wired"));
    std::process::ExitCode::SUCCESS
}
