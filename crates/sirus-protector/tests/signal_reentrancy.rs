//! Signal reentrancy proof: a SIGALRM handler may call the protected function
//! while the main thread is already executing it.

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
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static volatile sig_atomic_t armed;
static volatile sig_atomic_t hits;
static volatile sig_atomic_t bad;
static volatile unsigned long expected;

__attribute__((noinline, used))
unsigned long sirus_signal(unsigned long a, unsigned long b) {
    unsigned long x = a ^ (b + 0x9e3779b97f4a7c15UL);
    for (unsigned long i = 0; i < 200; i++) {
        x = (x ^ (x >> 13)) * 0xbf58476d1ce4e5b9UL;
        x ^= i;
    }
    return x;
}

static void handler(int signo) {
    (void)signo;
    if (armed) {
        unsigned long got = sirus_signal(7, 3);
        if (got != expected) {
            bad = 1;
        }
        hits++;
    }
}

int main(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGALRM, &action, 0);
    expected = sirus_signal(7, 3);
    struct itimerval timer;
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_usec = 50000;
    timer.it_interval.tv_usec = 50000;
    setitimer(ITIMER_REAL, &timer, 0);
    armed = 1;
    unsigned long acc = 0;
    for (unsigned long i = 0; i < 200; i++) {
        acc ^= sirus_signal(i, i * 3 + 1);
    }
    armed = 0;
    memset(&timer, 0, sizeof(timer));
    setitimer(ITIMER_REAL, &timer, 0);
    printf("%lu hits=%d bad=%d\n", acc, (int)hits, (int)bad);
    return 0;
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-signal-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("create sandbox");
    path
}

fn run(binary: &Path) -> Output {
    Command::new("timeout")
        .arg("120")
        .arg(binary)
        .output()
        .expect("run victim")
}

#[test]
fn signal_handler_can_reenter_protected_function() {
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

    let protected = directory.join("protected");
    let output = Command::new(env!("CARGO_BIN_EXE_sirus"))
        .arg("protect")
        .arg("--input")
        .arg(&native)
        .arg("--output")
        .arg(&protected)
        .arg("--function")
        .arg("sirus_signal")
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
    assert!(expected.status.success(), "native failed or timed out");
    let actual = run(&protected);
    assert!(
        actual.status.success(),
        "protected failed or timed out: {}",
        String::from_utf8_lossy(&actual.stderr)
    );

    let expected_text = String::from_utf8(expected.stdout).expect("native stdout");
    let actual_text = String::from_utf8(actual.stdout).expect("protected stdout");
    let expected_result = expected_text
        .split_whitespace()
        .next()
        .expect("native result");
    let mut fields = actual_text.split_whitespace();
    let actual_result = fields.next().expect("protected result");
    assert_eq!(actual_result, expected_result, "reentrant result mismatch");

    let hits = fields
        .find_map(|field| field.strip_prefix("hits="))
        .expect("protected hits")
        .parse::<u64>()
        .expect("numeric hits");
    let bad = fields
        .find_map(|field| field.strip_prefix("bad="))
        .expect("protected bad flag")
        .parse::<u64>()
        .expect("numeric bad flag");
    assert!(hits > 0, "the signal handler never fired during the run");
    assert_eq!(bad, 0, "the handler observed a corrupted result");
}
