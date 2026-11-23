//! Dudect-style Welch t-test measurements.
//!
//! The test is ignored by default because it is a statistical measurement, not
//! a correctness unit test. `scripts/dudect-check.sh` runs it and reports both
//! the constant-time cipher path and the deliberately data-dependent VM branch
//! path.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_arithmetic,
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    clippy::missing_const_for_fn,
    clippy::print_stdout,
    clippy::too_many_lines,
    reason = "statistical timing harness measures code outside the shipped no_std crates"
)]

use core::hint::black_box;
use std::time::Instant;

use sirus_core::lifter::lift_function;
use sirus_core::program::{CompileOptions, compile};
use sirus_vm::engine::{Status, VmInput, execute};
use sirus_vm::shared::chacha::ChaCha20;

const CRYPTO_BATCH: usize = 32;
const VM_BATCH: usize = 4;
const SAMPLES: usize = 120_000;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}

fn mean_variance(samples: &[u128]) -> (f64, f64) {
    let count = samples.len() as f64;
    let mean = samples.iter().map(|value| *value as f64).sum::<f64>() / count;
    let variance = samples
        .iter()
        .map(|value| {
            let difference = *value as f64 - mean;
            difference * difference
        })
        .sum::<f64>()
        / (count - 1.0);
    (mean, variance)
}

fn welch_t(first: &[u128], second: &[u128]) -> f64 {
    let (first_mean, first_variance) = mean_variance(first);
    let (second_mean, second_variance) = mean_variance(second);
    let denominator =
        (first_variance / first.len() as f64 + second_variance / second.len() as f64).sqrt();
    if denominator == 0.0 {
        return 0.0;
    }
    (first_mean - second_mean) / denominator
}

fn crypto_measurement() -> f64 {
    let mut rng = XorShift(0x1234_5678_9abc_def0);
    let first_key = [0x11_u8; 32];
    let second_key = [0x22_u8; 32];
    let nonce = [0x5a_u8; 12];
    let mut output = [0_u8; 64];
    let mut first_samples = Vec::with_capacity(SAMPLES / 2);
    let mut second_samples = Vec::with_capacity(SAMPLES / 2);
    for _ in 0..10_000 {
        let mut cipher = ChaCha20::new(first_key, nonce);
        cipher.fill(&mut output);
        black_box(output);
    }
    for _ in 0..SAMPLES {
        let first_class = rng.next() & 1 == 0;
        let started = Instant::now();
        for _ in 0..CRYPTO_BATCH {
            let mut cipher = ChaCha20::new(if first_class { first_key } else { second_key }, nonce);
            cipher.fill(&mut output);
            black_box(output);
        }
        let elapsed = started.elapsed().as_nanos();
        if first_class {
            first_samples.push(elapsed);
        } else {
            second_samples.push(elapsed);
        }
    }
    welch_t(&first_samples, &second_samples)
}

fn compile_branch_victim() -> sirus_core::program::CompiledProgram {
    // if a > b { a + b } else { a - b }
    let code = [
        0x48, 0x39, 0xf7, 0x76, 0x07, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89, 0xf8,
        0x48, 0x29, 0xf0, 0xc3,
    ];
    let function = lift_function(&code, 0x1000).expect("lift");
    let mut options = CompileOptions::new();
    options.decoys = 2;
    compile(&[function], [0x6d_u8; 32], options).expect("compile")
}

fn vm_measurement() -> f64 {
    let program = compile_branch_victim();
    let mut rng = XorShift(0x0f0e_0d0c_0b0a_0908);
    let mut first_samples = Vec::with_capacity(SAMPLES / 2);
    let mut second_samples = Vec::with_capacity(SAMPLES / 2);
    let run = |args: [u64; 6]| {
        let result = execute(
            VmInput::new(
                program.payload(),
                program.seed(),
                program.expected_hash(),
                program.base_a(),
                program.base_b(),
                program.entry_states(),
                program.fuel(),
            ),
            0,
            args,
        );
        assert_eq!(result.status, Status::Returned);
        black_box(result.value)
    };
    for _ in 0..1000 {
        run([7, 3, 0, 0, 0, 0]);
        run([3, 7, 0, 0, 0, 0]);
    }
    for _ in 0..SAMPLES {
        let first_class = rng.next() & 1 == 0;
        let started = Instant::now();
        for _ in 0..VM_BATCH {
            run(if first_class {
                [7, 3, 0, 0, 0, 0]
            } else {
                [3, 7, 0, 0, 0, 0]
            });
        }
        let elapsed = started.elapsed().as_nanos();
        if first_class {
            first_samples.push(elapsed);
        } else {
            second_samples.push(elapsed);
        }
    }
    welch_t(&first_samples, &second_samples)
}

#[test]
#[ignore = "statistical timing measurement; run through scripts/dudect-check.sh"]
fn dudect_style_timing() {
    let crypto_t = crypto_measurement();
    let vm_t = vm_measurement();
    println!("DUDECT crypto_t={crypto_t:.3} vm_t={vm_t:.3} samples={SAMPLES}");
    assert!(
        crypto_t.abs() < 10.0,
        "cipher timing differs under the dudect threshold"
    );
}
