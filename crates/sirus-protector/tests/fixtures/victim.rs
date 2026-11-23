#![forbid(unsafe_code)]

#[inline(never)]
fn sirus_demo_check(a: u64, b: u64) -> u64 {
    if a > b {
        a.wrapping_mul(3)
            .wrapping_add(b)
            ^ 0xa5a5_5a5a_1234_5678
    } else {
        (b ^ a).wrapping_add(0x1234_5678_9abc_def0)
    }
}

#[inline(never)]
fn sirus_demo_loop(a: u64, b: u64) -> u64 {
    let mut accumulator = a.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut index = 0_u64;
    let limit = b & 7;
    while index < limit {
        accumulator = accumulator.rotate_left(5) ^ a.wrapping_add(index);
        index = index.wrapping_add(1);
    }
    accumulator
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let first = arguments.next().and_then(|v| v.parse().ok()).unwrap_or(7);
    let second = arguments.next().and_then(|v| v.parse().ok()).unwrap_or(3);
    println!("{}", sirus_demo_check(first, second));
    println!("{}", sirus_demo_loop(first, second));
}
