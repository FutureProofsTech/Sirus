#![no_main]

use libfuzzer_sys::fuzz_target;
use sirus_vm::engine::{execute, VmInput};
use sirus_vm::shared::cipher::{base_key, payload_hash};

fuzz_target!(|data: &[u8]| {
    let mut seed = [0x5a_u8; 32];
    let copy = data.len().min(32);
    seed[..copy].copy_from_slice(&data[..copy]);
    let payload = if data.len() > 32 { &data[32..] } else { &[] };
    let expected_hash = payload_hash(&seed, payload);
    let base = base_key(&seed);
    let states = [[0_u64, 0_u64]];
    let _ = execute(
        VmInput::new(payload, &seed, expected_hash, base, 0, &states, 1_000_000),
        0,
        [
            u64::from_le_bytes([data.first().copied().unwrap_or(0); 8]),
            0,
            0,
            0,
            0,
            0,
        ],
    );
});
