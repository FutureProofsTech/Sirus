//! End-to-end proof for 32-bit lane, multiply, unpack, and movq SSE2 forms.

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

static const unsigned long sirus_math_table[4] = {
    0x0000000200000003UL, 0x0000000400000005UL,
    0x0000000600000007UL, 0x0000000800000009UL
};

__attribute__((noinline, used))
unsigned long sirus_sse2_math(unsigned long index) {
    unsigned long out[2] = {0, 0};
    __asm__ volatile(
        "movdqu (%2), %%xmm0\n\t"
        "movdqu (%3), %%xmm1\n\t"
        "paddd %%xmm1, %%xmm0\n\t"
        "psubd %%xmm1, %%xmm0\n\t"
        "pmuludq %%xmm1, %%xmm0\n\t"
        "punpcklqdq %%xmm1, %%xmm0\n\t"
        "movdqu %%xmm0, (%4)\n\t"
        : "=m"(out[0]), "=m"(out[1])
        : "r"(sirus_math_table), "r"(sirus_math_table + 2), "r"(out)
        : "xmm0", "xmm1", "memory");
    return out[0] ^ out[1] ^ index;
}

int main(int argc, char **argv) {
    unsigned long index = argc > 1 ? strtoul(argv[1], 0, 0) : 0;
    printf("%lu\n", sirus_sse2_math(index));
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-sse2m-{}-{nanos}", std::process::id()));
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
fn sse2_math_forms_execute_end_to_end() {
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
            .arg("sirus_sse2_math")
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
        for argument in ["0", "1", "2", "3", "0xffffffffffffffff"] {
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
