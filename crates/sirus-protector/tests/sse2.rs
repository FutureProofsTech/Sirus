//! Real end-to-end proof for the supported SSE2 subset.

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

static const unsigned long sirus_sse_table[4] = {
    0x0123456789abcdefUL, 0xfedcba9876543210UL,
    0x1111222233334444UL, 0x5555666677778888UL
};

__attribute__((noinline, used))
unsigned long sirus_sse_demo(unsigned long index) {
    const unsigned long *p = sirus_sse_table + (index & 2);
    unsigned long out[2] = {0, 0};
    __asm__ volatile(
        "movdqu (%2), %%xmm0\n\t"
        "pxor %%xmm1, %%xmm1\n\t"
        "paddq %%xmm0, %%xmm0\n\t"
        "movdqu %%xmm0, (%3)\n\t"
        : "=m"(out[0]), "=m"(out[1])
        : "r"(p), "r"(out)
        : "xmm0", "xmm1", "memory");
    return out[0] ^ out[1];
}

int main(int argc, char **argv) {
    unsigned long index = argc > 1 ? strtoul(argv[1], 0, 0) : 0;
    printf("%lu\n", sirus_sse_demo(index));
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-sse-{}-{nanos}", std::process::id()));
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
fn sse2_subset_executes_end_to_end() {
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
            .arg("sirus_sse_demo")
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
        for argument in ["0", "1", "2", "3", "4", "5", "6", "7"] {
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
