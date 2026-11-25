//! End-to-end proof for direct calls between protected functions.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration test uses assertion panics and fixed fixtures"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const VICTIM: &str = r#"
#include <stdio.h>
#include <stdlib.h>

static const unsigned long sirus_call_table[4] = {
    0x0123456789abcdefUL, 0xfedcba9876543210UL,
    0x1111222233334444UL, 0x5555666677778888UL
};

__attribute__((noinline, used))
unsigned long sirus_callee(unsigned long a, unsigned long b) {
    return sirus_call_table[a & 3] ^ (b + 0x55);
}

__attribute__((noinline, used))
unsigned long sirus_caller(unsigned long a, unsigned long b) {
    unsigned long value = sirus_callee(a, b);
    return value + (a & 1) + 7;
}

int main(int argc, char **argv) {
    unsigned long a = argc > 1 ? strtoul(argv[1], 0, 0) : 0;
    unsigned long b = argc > 2 ? strtoul(argv[2], 0, 0) : 0;
    printf("%lu\n", sirus_caller(a, b));
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-call-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("create sandbox");
    path
}

fn run(binary: &Path, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .output()
        .expect("run victim")
}

#[test]
fn direct_calls_between_protected_functions_execute() {
    let directory = sandbox();
    let source = directory.join("victim.c");
    let native = directory.join("native");
    fs::write(&source, VICTIM).expect("write victim");
    let compiled = Command::new("cc")
        .arg("-O2")
        .arg("-fno-optimize-sibling-calls")
        .arg("-fPIE")
        .arg("-pie")
        .arg("-o")
        .arg(&native)
        .arg(&source)
        .output()
        .expect("compile victim");
    assert!(
        compiled.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let protected = directory.join("protected");
    let output = Command::new(env!("CARGO_BIN_EXE_sirus"))
        .arg("protect")
        .arg("--input")
        .arg(&native)
        .arg("--output")
        .arg(&protected)
        .arg("--function")
        .arg("sirus_caller")
        .arg("--function")
        .arg("sirus_callee")
        .arg("--seed")
        .arg("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .output()
        .expect("run protector");
    assert!(
        output.status.success(),
        "protect failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    for arguments in [
        &["0", "0"][..],
        &["1", "2"][..],
        &["3", "4"][..],
        &["0xffffffffffffffff", "7"][..],
    ] {
        let expected = run(&native, arguments);
        let actual = run(&protected, arguments);
        assert!(expected.status.success(), "native failed for {arguments:?}");
        assert!(
            actual.status.success(),
            "protected failed for {arguments:?}: {}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert_eq!(
            actual.stdout, expected.stdout,
            "output mismatch for {arguments:?}"
        );
    }

    let constant_time = directory.join("constant-time");
    let output = Command::new(env!("CARGO_BIN_EXE_sirus"))
        .arg("protect")
        .arg("--input")
        .arg(&native)
        .arg("--output")
        .arg(&constant_time)
        .arg("--function")
        .arg("sirus_caller")
        .arg("--function")
        .arg("sirus_callee")
        .arg("--constant-time")
        .arg("--seed")
        .arg("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .output()
        .expect("run protector");
    assert!(
        !output.status.success(),
        "constant-time calls must fail closed until a fixed-path call runner exists"
    );
}
