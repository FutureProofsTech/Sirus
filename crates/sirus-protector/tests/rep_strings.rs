//! End-to-end proof for `rep movsb` and `rep stosb` on private memory.

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
unsigned long sirus_rep_demo(unsigned long n) {
    unsigned char src[64];
    unsigned char dst[64];
    unsigned long count = n & 31;
    for (unsigned long i = 0; i < 64; i++) {
        src[i] = (unsigned char)(i ^ 0x5a);
        dst[i] = 0;
    }
    unsigned char *sp = src;
    unsigned char *dp = dst;
    __asm__ volatile(
        "rep movsb"
        : "+D"(dp), "+S"(sp), "+c"(count)
        :
        : "memory");
    dp = dst;
    count = n & 31;
    __asm__ volatile(
        "rep stosb"
        : "+D"(dp), "+c"(count)
        : "a"(0x33)
        : "memory");
    return dst[0] ^ dst[15] ^ count;
}

int main(int argc, char **argv) {
    unsigned long n = argc > 1 ? strtoul(argv[1], 0, 0) : 0;
    printf("%lu\n", sirus_rep_demo(n));
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-rep-{}-{nanos}", std::process::id()));
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
fn repeated_string_operations_execute_end_to_end() {
    let directory = sandbox();
    let source = directory.join("victim.c");
    let native = directory.join("native");
    fs::write(&source, VICTIM).expect("write victim");
    let compiled = Command::new("cc")
        .arg("-O2")
        .arg("-fno-builtin")
        .arg("-fno-tree-vectorize")
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
        .arg("sirus_rep_demo")
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

    for argument in ["0", "1", "7", "15", "31", "32", "63"] {
        let expected = run(&native, argument);
        let actual = run(&protected, argument);
        assert!(expected.status.success(), "native failed for {argument}");
        assert!(
            actual.status.success(),
            "protected failed for {argument}: {}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert_eq!(
            actual.stdout, expected.stdout,
            "output mismatch for {argument}"
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
        .arg("sirus_rep_demo")
        .arg("--constant-time")
        .arg("--seed")
        .arg("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .output()
        .expect("run protector");
    assert!(
        !output.status.success(),
        "constant-time repeated-string operations must fail closed"
    );
}
