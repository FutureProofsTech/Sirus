#![forbid(unsafe_code)]

//! Minimal call-overhead victim. The protector is applied by
//! `scripts/bench-overhead.sh`; this file is not part of the shipped workspace.

use std::hint::black_box;
use std::time::Instant;

#[inline(never)]
fn sirus_demo_check(a: u64, b: u64) -> u64 {
    if a > b {
        a.wrapping_mul(3).wrapping_add(b) ^ 0xa5a5_5a5a_1234_5678
    } else {
        (b ^ a).wrapping_add(0x1234_5678_9abc_def0)
    }
}

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100_000);
    let mut accumulator = 0_u64;
    let started = Instant::now();
    let mut index = 0_u64;
    while index < iterations {
        let first = index.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x55aa_55aa_55aa_55aa;
        let second = index.rotate_left(17) ^ 0x1234_5678_9abc_def0;
        accumulator = accumulator.wrapping_add(black_box(sirus_demo_check(
            black_box(first),
            black_box(second),
        )));
        index = index.wrapping_add(1);
    }
    let elapsed = started.elapsed();
    let per_call = elapsed.as_secs_f64() * 1e9 / iterations as f64;
    println!("iterations={iterations} ns_per_call={per_call:.2} checksum={accumulator:016x}");
}
