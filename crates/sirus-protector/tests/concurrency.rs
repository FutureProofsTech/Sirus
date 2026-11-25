//! Reentrancy proof: concurrent protected calls must not share VM state.

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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline, used))
unsigned long sirus_concurrent(unsigned long a, unsigned long b) {
    unsigned long x = a ^ (b + 0x9e3779b97f4a7c15UL);
    x = (x << 7 | x >> 57) + (a & 0xffff);
    x ^= b * 0xbf58476d1ce4e5b9UL;
    return x;
}

struct work {
    unsigned long seed;
    unsigned long result;
};

static void *worker(void *argument) {
    struct work *work = (struct work *)argument;
    unsigned long state = work->seed;
    unsigned long result = 0;
    for (unsigned long i = 0; i < 50000; i++) {
        state = state * 6364136223846793005UL + 1;
        result ^= sirus_concurrent(state, state >> 17);
    }
    work->result = result;
    return 0;
}

int main(void) {
    pthread_t threads[8];
    struct work work[8];
    for (unsigned long i = 0; i < 8; i++) {
        work[i].seed = 0x123456789abcdef0UL + i;
        work[i].result = 0;
        if (pthread_create(&threads[i], 0, worker, &work[i]) != 0) return 1;
    }
    unsigned long result = 0;
    for (unsigned long i = 0; i < 8; i++) {
        pthread_join(threads[i], 0);
        result ^= work[i].result;
    }
    printf("%lu\n", result);
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-conc-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("create sandbox");
    path
}

fn run(binary: &Path) -> Output {
    Command::new(binary).output().expect("run victim")
}

#[test]
fn concurrent_protected_calls_are_isolated() {
    let directory = sandbox();
    let source = directory.join("victim.c");
    let native = directory.join("native");
    fs::write(&source, VICTIM).expect("write victim");
    let compiled = Command::new("cc")
        .arg("-O2")
        .arg("-pthread")
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

    let protected = directory.join("protected");
    let output = Command::new(env!("CARGO_BIN_EXE_sirus"))
        .arg("protect")
        .arg("--input")
        .arg(&native)
        .arg("--output")
        .arg(&protected)
        .arg("--function")
        .arg("sirus_concurrent")
        .arg("--profile")
        .arg("fast")
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

    let expected = run(&native);
    let actual = run(&protected);
    assert!(expected.status.success(), "native failed");
    assert!(
        actual.status.success(),
        "protected failed: {}",
        String::from_utf8_lossy(&actual.stderr)
    );
    assert_eq!(actual.stdout, expected.stdout, "concurrent output mismatch");
}
