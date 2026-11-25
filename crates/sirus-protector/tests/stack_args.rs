//! Real end-to-end proof for 7th and later stack arguments.

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

__attribute__((noinline, used))
unsigned long sirus_stack_demo(
    unsigned long a, unsigned long b, unsigned long c, unsigned long d,
    unsigned long e, unsigned long f, unsigned long g, unsigned long h) {
    return a ^ (b + c) ^ (d * 3) ^ (e >> 2) ^ (f << 1) ^ (g * 5) ^ (h + 7);
}

int main(int argc, char **argv) {
    unsigned long values[8] = {0};
    for (int index = 0; index < 8 && index + 1 < argc; index++) {
        values[index] = strtoul(argv[index + 1], 0, 0);
    }
    printf("%lu\n", sirus_stack_demo(
        values[0], values[1], values[2], values[3],
        values[4], values[5], values[6], values[7]));
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-stack-{}-{nanos}", std::process::id()));
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
fn stack_arguments_execute_end_to_end() {
    let directory = sandbox();
    let source = directory.join("victim.c");
    let native = directory.join("native");
    fs::write(&source, VICTIM).expect("write victim");
    let compiled = Command::new("cc")
        .arg("-O2")
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

    let modes: &[(&str, &[&str])] = &[
        ("normal", &[]),
        (
            "constant-time",
            &["--constant-time", "--constant-time-passes", "64"],
        ),
    ];
    let cases: &[&[&str]] = &[
        &["1", "2", "3", "4", "5", "6", "7", "8"],
        &["0", "0", "0", "0", "0", "0", "0", "0"],
        &["0xffffffffffffffff", "2", "3", "4", "5", "6", "7", "8"],
        &["9", "8", "7", "6", "5", "4", "3", "2"],
    ];
    for (mode, extra) in modes {
        let protected = directory.join(format!("protected-{mode}"));
        let output = Command::new(env!("CARGO_BIN_EXE_sirus"))
            .arg("protect")
            .arg("--input")
            .arg(&native)
            .arg("--output")
            .arg(&protected)
            .arg("--function")
            .arg("sirus_stack_demo")
            .arg("--seed")
            .arg("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
            .args(*extra)
            .output()
            .expect("run protector");
        assert!(
            output.status.success(),
            "{mode} protect failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        for arguments in cases {
            let expected = run(&native, arguments);
            let actual = run(&protected, arguments);
            assert!(expected.status.success(), "native failed for {arguments:?}");
            assert!(
                actual.status.success(),
                "{mode} protected failed for {arguments:?}: {}",
                String::from_utf8_lossy(&actual.stderr)
            );
            assert_eq!(
                actual.stdout, expected.stdout,
                "{mode} output mismatch for {arguments:?}"
            );
        }
    }
}
