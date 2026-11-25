//! Constant-time branch/store regression: inactive blocks must not write memory.

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
unsigned long sirus_ct_mem(unsigned long a) {
    unsigned long out[4] = {1, 2, 3, 4};
    volatile unsigned long *view = out;
    if (a & 1) {
        view[0] = 0x11;
    } else {
        view[1] = 0x22;
    }
    for (unsigned long i = 0; i < 4; i++) {
        view[i] ^= (a >> (i * 8)) & 0xff;
    }
    return out[0] ^ out[1] ^ out[2] ^ out[3];
}

int main(int argc, char **argv) {
    unsigned long a = argc > 1 ? strtoul(argv[1], 0, 0) : 0;
    printf("%lu\n", sirus_ct_mem(a));
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-ctmem-{}-{nanos}", std::process::id()));
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
fn constant_time_inactive_stores_do_not_corrupt_memory() {
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
        .arg("sirus_ct_mem")
        .arg("--constant-time")
        .arg("--constant-time-passes")
        .arg("64")
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

    for argument in [
        "0",
        "1",
        "2",
        "3",
        "255",
        "256",
        "65535",
        "0xffffffffffffffff",
    ] {
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
}
