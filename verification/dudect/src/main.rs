use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use sirus_core::lifter::lift_function;
use sirus_core::program::{CompileOptions, compile};
use sirus_vm::engine::{Status, VmInput, execute};
use sirus_vm::shared::chacha::ChaCha20;

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

fn crypto(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let first_key = [0x11_u8; 32];
    let second_key = [0x22_u8; 32];
    let nonce = [0x5a_u8; 12];
    let mut random = XorShift(0x1234_5678_9abc_def0);
    for _ in 0..200_000 {
        let left = random.next() & 1 == 0;
        let key = if left { first_key } else { second_key };
        runner.run_one(
            if left { Class::Left } else { Class::Right },
            || {
                let mut output = [0_u8; 64];
                let mut cipher = ChaCha20::new(key, nonce);
                cipher.fill(&mut output);
                std::hint::black_box(output);
            },
        );
    }
}

fn vm(runner: &mut CtRunner, _rng: &mut BenchRng) {
    // if a > b { a + b } else { a - b }
    let code = [
        0x48, 0x39, 0xf7, 0x76, 0x07, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89, 0xf8,
        0x48, 0x29, 0xf0, 0xc3,
    ];
    let function = lift_function(&code, 0x1000).expect("lift");
    let mut options = CompileOptions::new();
    options.decoys = 2;
    let program = compile(&[function], [0x6d_u8; 32], options).expect("compile");
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
        result.value
    };
    let mut random = XorShift(0x0f0e_0d0c_0b0a_0908);
    for _ in 0..100_000 {
        let left = random.next() & 1 == 0;
        runner.run_one(
            if left { Class::Left } else { Class::Right },
            || {
                std::hint::black_box(run(if left {
                    [7, 3, 0, 0, 0, 0]
                } else {
                    [3, 7, 0, 0, 0, 0]
                }));
            },
        );
    }
}

ctbench_main!(crypto, vm);
