//! Real end-to-end proof for RIP-relative read-only data.

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

static const volatile unsigned long sirus_table[8] = {
    0x0123456789abcdefUL, 0xfedcba9876543210UL, 0x1111222233334444UL,
    0x5555666677778888UL, 0x9999aaaabbbbccccUL, 0xddddeeeeffff0000UL,
    0x0f0f0f0f0f0f0f0fUL, 0xf0f0f0f0f0f0f0f0UL
};

__attribute__((noinline, used))
unsigned long sirus_rip_demo(unsigned long index) {
    return sirus_table[index & 7] + (index >> 3);
}

int main(int argc, char **argv) {
    unsigned long index = argc > 1 ? strtoul(argv[1], 0, 0) : 0;
    printf("%lu\n", sirus_rip_demo(index));
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-rip-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("create sandbox");
    path
}

fn run(binary: &Path, argument: &str) -> Output {
    Command::new(binary)
        .arg(argument)
        .output()
        .expect("run victim")
}

#[test]
fn rip_relative_read_only_data_executes_end_to_end() {
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
    for (mode, extra) in modes {
        let protected = directory.join(format!("protected-{mode}"));
        let output = Command::new(env!("CARGO_BIN_EXE_sirus"))
            .arg("protect")
            .arg("--input")
            .arg(&native)
            .arg("--output")
            .arg(&protected)
            .arg("--function")
            .arg("sirus_rip_demo")
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

        for argument in ["0", "1", "7", "9", "123456789"] {
            let expected = run(&native, argument);
            let actual = run(&protected, argument);
            assert!(expected.status.success(), "native failed for {argument}");
            assert!(
                actual.status.success(),
                "{mode} protected failed for {argument}: {}",
                String::from_utf8_lossy(&actual.stderr)
            );
            assert_eq!(
                actual.stdout, expected.stdout,
                "{mode} output mismatch for {argument}"
            );
        }
    }
}
