#![no_main]

use libfuzzer_sys::fuzz_target;
use sirus_core::lifter::lift_function;
use sirus_core::program::{CompileOptions, compile};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    if let Ok(function) = lift_function(data, 0x1000) {
        let mut options = CompileOptions::new();
        options.decoys = 0;
        options.constant_time = data.first().is_some_and(|value| value & 1 != 0);
        let _ = compile(&[function], [0x42_u8; 32], options);
    }
});
