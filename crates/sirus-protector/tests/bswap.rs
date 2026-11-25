//! End-to-end proof for byte-swap instructions.

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
unsigned long sirus_bswap_demo(unsigned long value) {
    return __builtin_bswap64(value) ^ (unsigned long)__builtin_bswap32((unsigned int)value);
}

int main(int argc, char **argv) {
    unsigned long value = argc > 1 ? strtoul(argv[1], 0, 0) : 0;
    printf("%lu\n", sirus_bswap_demo(value));
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-bswap-{}-{nanos}", std::process::id()));
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
fn bswap_executes_end_to_end() {
    let directory = sandbox();
    let source = directory.join("victim.c");
    let native = directory.join("native");
    fs::write(&source, VICTIM).expect("write victim");
    let compiled = Command::new("cc")
        .arg("-O2")
        .arg("-fno-builtin")
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

    for mode in ["normal", "constant-time"] {
        let protected = directory.join(format!("protected-{mode}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_sirus"));
        command
            .arg("protect")
            .arg("--input")
            .arg(&native)
            .arg("--output")
            .arg(&protected)
            .arg("--function")
            .arg("sirus_bswap_demo")
            .arg("--seed")
            .arg("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        if mode == "constant-time" {
            command
                .arg("--constant-time")
                .arg("--constant-time-passes")
                .arg("64");
        }
        let output = command.output().expect("run protector");
        assert!(
            output.status.success(),
            "{mode} protect failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        for argument in ["0", "1", "0x0123456789abcdef", "0xffffffffffffffff"] {
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
