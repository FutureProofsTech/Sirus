//! Error-path coverage for the CLI and protection pipeline.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration test uses assertion panics and fixed fixture files"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sirus"))
}

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-errors-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("sandbox");
    path
}

fn compile_victim(sandbox: &Path) -> PathBuf {
    let output_path = sandbox.join("victim");
    let output = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()))
        .arg("--edition=2021")
        .arg("-C")
        .arg("opt-level=2")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("debuginfo=0")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/victim.rs"
        ))
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("rustc victim");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output_path
}

fn run_protect(input: &Path, output: &Path, extra: &[&str]) -> Output {
    let mut command = Command::new(binary());
    command
        .arg("protect")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .arg("--seed")
        .arg("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    command.args(extra);
    command.output().expect("run protector")
}

#[test]
fn protection_error_paths_are_typed_and_nonzero() {
    let sandbox = sandbox();
    let victim = compile_victim(&sandbox);
    let output = sandbox.join("out");

    let missing = run_protect(
        Path::new("/definitely/missing"),
        &output,
        &["--function", "x"],
    );
    assert!(!missing.status.success());
    assert_eq!(missing.status.code(), Some(2));

    let pe = sandbox.join("fake.exe");
    fs::write(&pe, b"MZ").expect("fake PE");
    let pe_result = run_protect(&pe, &output, &["--function", "x"]);
    assert!(!pe_result.status.success());
    assert_eq!(pe_result.status.code(), Some(1));

    let not_found = run_protect(&victim, &output, &["--function-contains", "missing_target"]);
    assert!(!not_found.status.success());
    assert_eq!(not_found.status.code(), Some(1));

    let ambiguous = run_protect(&victim, &output, &["--function-contains", "sirus_demo"]);
    assert!(!ambiguous.status.success());
    assert_eq!(ambiguous.status.code(), Some(1));

    let bad_vm_base = run_protect(
        &victim,
        &output,
        &["--function-contains", "sirus_demo_check", "--vm-base", "0"],
    );
    assert!(!bad_vm_base.status.success());
    assert_eq!(bad_vm_base.status.code(), Some(1));

    let bad_seed = Command::new(binary())
        .arg("protect")
        .arg("--input")
        .arg(&victim)
        .arg("--output")
        .arg(&output)
        .arg("--function-contains")
        .arg("sirus_demo_check")
        .arg("--seed")
        .arg("bad")
        .output()
        .expect("bad seed");
    assert!(!bad_seed.status.success());
    assert_eq!(bad_seed.status.code(), Some(2));

    let bad_marker = run_protect(&victim, &output, &["--marker-begin", "aa"]);
    assert!(!bad_marker.status.success());
    assert_eq!(bad_marker.status.code(), Some(2));

    let malformed = sandbox.join("malformed");
    fs::write(&malformed, b"not a binary").expect("malformed");
    let inspect = Command::new(binary())
        .arg("inspect")
        .arg(&malformed)
        .output()
        .expect("inspect malformed");
    assert!(!inspect.status.success());
    assert_eq!(inspect.status.code(), Some(1));

    let version = Command::new(binary())
        .arg("version")
        .output()
        .expect("version");
    assert!(version.status.success());

    drop(fs::remove_dir_all(sandbox));
}
