// Standalone Wine test host. This file is not part of the shipped protector;
// `no_mangle` creates the stable COFF symbols that the PE selector resolves.
#![allow(unsafe_code)]

#[no_mangle]
#[inline(never)]
pub extern "C" fn sirus_win_check(a: u64, b: u64) -> u64 {
    if a > b {
        a.wrapping_mul(3)
            .wrapping_add(b)
            ^ 0xa5a5_5a5a_1234_5678
    } else {
        (b ^ a).wrapping_add(0x1234_5678_9abc_def0)
    }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn sirus_win_mix(a: u64, b: u64) -> u64 {
    let mut acc = 0_u64;
    let mut index = 0_u64;
    while index < (a & 7) {
        acc = acc.wrapping_add(b).wrapping_mul(3);
        index = index.wrapping_add(1);
    }
    acc ^ 0x0123_4567_89ab_cdef
}

fn main() {
    for (a, b) in [(7_u64, 3_u64), (3, 7), (0, 0), (123_456_789, 5)] {
        println!(
            "{} {}",
            sirus_win_check(a, b),
            sirus_win_mix(a, b)
        );
    }
}
