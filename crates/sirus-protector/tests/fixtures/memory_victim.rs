#![forbid(unsafe_code)]

/// Unique constant used by the live-memory diagnostic fixture.
const SIRUS_MEMORY_SECRET: u64 = 0x1357_9bdf_2468_ace0;

#[inline(never)]
fn sirus_demo_long(seed: u64, iterations: u64) -> u64 {
    let mut value = seed;
    let mut index = 0_u64;
    while index < iterations {
        value = value
            .wrapping_mul(SIRUS_MEMORY_SECRET)
            .rotate_left(7)
            ^ index;
        index = index.wrapping_add(1);
    }
    value
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let seed = arguments.next().and_then(|v| v.parse().ok()).unwrap_or(7);
    let iterations = arguments
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000_000);
    println!("{}", sirus_demo_long(seed, iterations));
}
