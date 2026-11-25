#![forbid(unsafe_code)]

//! Cachegrind victim for the constant-time branch path. The protected leaf is
//! the same supported shape used by the overhead benchmark; input differences
//! must not change the executed instruction or cache footprint.

use std::hint::black_box;

#[inline(never)]
fn sirus_demo_ct(a: u64, b: u64) -> u64 {
    if a > b {
        a.wrapping_mul(3).wrapping_add(b) ^ 0xa5a5_5a5a_1234_5678
    } else {
        (b ^ a).wrapping_add(0x1234_5678_9abc_def0)
    }
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let a = arguments
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(7);
    let b = arguments
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(3);
    let iterations = arguments
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(4);
    let mut checksum = 0_u64;
    let mut index = 0_u64;
    while index < iterations {
        checksum = checksum.wrapping_add(black_box(sirus_demo_ct(
            black_box(a.wrapping_add(index & 1)),
            black_box(b),
        )));
        index = index.wrapping_add(1);
    }
    std::hint::black_box(checksum);
    println!("done");
}
