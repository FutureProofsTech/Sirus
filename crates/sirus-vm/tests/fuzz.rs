//! Deterministic adversarial fuzzing of the VM decode/execute surface.
//!
//! The harness intentionally feeds random and mutated payloads. Success means
//! no panic, no hang, bounded steps, and a valid status for every input.

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::large_stack_arrays,
    reason = "fuzz test uses assertion panics and fixed-size random buffers"
)]

use sirus_core::lifter::lift_function;
use sirus_core::program::{CompileOptions, compile};
use sirus_vm::engine::{Status, VmInput, execute};

#[derive(Clone, Debug)]
struct SplitMix {
    state: u64,
}

impl SplitMix {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % u64::try_from(bound).unwrap_or(1)).unwrap_or(0)
    }
}

fn check_result(status: Status, steps: u64, fuel: u64) {
    assert!(steps <= fuel);
    match status {
        Status::Returned | Status::BadPayload | Status::FuelExhausted | Status::Trap => {}
        _ => panic!("unknown VM status"),
    }
}

#[test]
fn random_payloads_never_panic_or_overrun_fuel() {
    let mut rng = SplitMix::new(0x5eed_cafe_f00d_1234);
    let mut payload = vec![0_u8; 4096];
    let mut iteration = 0_usize;
    while iteration < 20_000 {
        let length = rng.below(2048).saturating_add(1);
        let mut index = 0_usize;
        while index < length {
            if let Some(slot) = payload.get_mut(index) {
                *slot = u8::try_from(rng.next_u64() & 0xff).unwrap_or(0);
            }
            index = index.saturating_add(1);
        }
        let mut seed = [0_u8; 32];
        for byte in &mut seed {
            *byte = u8::try_from(rng.next_u64() & 0xff).unwrap_or(0);
        }
        let entry_states = [[rng.next_u64(), rng.next_u64()], [1, 2]];
        let fuel = u64::try_from(rng.below(4096).saturating_add(1)).unwrap_or(1);
        let result = execute(
            VmInput::new(
                payload.get(..length).unwrap_or(&[]),
                &seed,
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
                &entry_states,
                fuel,
            ),
            rng.below(3),
            [rng.next_u64(), rng.next_u64(), rng.next_u64(), 0, 0, 0],
        );
        check_result(result.status, result.steps, fuel);
        iteration = iteration.saturating_add(1);
    }
}

#[test]
fn mutations_of_a_valid_payload_never_panic() {
    let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
    let function = lift_function(&code, 0x1000).expect("lift");
    let program = compile(&[function], [0x42_u8; 32], CompileOptions::new()).expect("compile");
    let base = program.payload().to_vec();
    let mut rng = SplitMix::new(0xdead_beef_1234_5678);
    let mut iteration = 0_usize;
    while iteration < 10_000 {
        let mut payload = base.clone();
        let mutations = rng.below(8).saturating_add(1);
        let mut mutation = 0_usize;
        while mutation < mutations {
            let index = rng.below(payload.len());
            if let Some(byte) = payload.get_mut(index) {
                *byte ^= u8::try_from(rng.next_u64() & 0xff).unwrap_or(1);
            }
            mutation = mutation.saturating_add(1);
        }
        let fuel = 200_000_u64;
        let result = execute(
            VmInput::new(
                &payload,
                program.seed(),
                program.expected_hash(),
                program.base_a(),
                program.base_b(),
                program.entry_states(),
                fuel,
            ),
            0,
            [rng.next_u64(), rng.next_u64(), 0, 0, 0, 0],
        );
        check_result(result.status, result.steps, fuel);
        iteration = iteration.saturating_add(1);
    }
}
