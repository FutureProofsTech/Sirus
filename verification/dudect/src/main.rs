use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use sirus_core::lifter::lift_function;
use sirus_core::program::{compile, CompileOptions};
use sirus_vm::engine::{execute, execute_oblivious, Status, VmInput};
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

fn run_oblivious(program: &sirus_core::program::CompiledProgram, args: [u64; 6]) -> u64 {
    let result = execute_oblivious(
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
        usize::from(program.constant_time_passes()),
    );
    assert_eq!(result.status, Status::Returned);
    result.value
}

fn crypto(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let first_key = [0x11_u8; 32];
    let second_key = [0x22_u8; 32];
    let nonce = [0x5a_u8; 12];
    let mut random = XorShift(0x1234_5678_9abc_def0);
    for _ in 0..200_000 {
        let left = random.next() & 1 == 0;
        let key = if left { first_key } else { second_key };
        runner.run_one(if left { Class::Left } else { Class::Right }, || {
            let mut output = [0_u8; 64];
            let mut cipher = ChaCha20::new(key, nonce);
            cipher.fill(&mut output);
            std::hint::black_box(output);
        });
    }
}

fn crypto_same(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let key = [0x11_u8; 32];
    let nonce = [0x5a_u8; 12];
    let mut random = XorShift(0x1357_9bdf_2468_ace0);
    for _ in 0..200_000 {
        let left = random.next() & 1 == 0;
        runner.run_one(if left { Class::Left } else { Class::Right }, || {
            let mut output = [0_u8; 64];
            let mut cipher = ChaCha20::new(key, nonce);
            cipher.fill(&mut output);
            std::hint::black_box(output);
        });
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
        runner.run_one(if left { Class::Left } else { Class::Right }, || {
            std::hint::black_box(run(if left {
                [7, 3, 0, 0, 0, 0]
            } else {
                [3, 7, 0, 0, 0, 0]
            }));
        });
    }
}

fn vm_constant(runner: &mut CtRunner, _rng: &mut BenchRng) {
    // Straight-line: imul rax, rsi; ret
    let code = [0x48, 0x89, 0xf8, 0x48, 0x0f, 0xaf, 0xc6, 0xc3];
    let function = lift_function(&code, 0x1000).expect("lift");
    let mut options = CompileOptions::new();
    options.constant_time = true;
    options.mba_depth = 0;
    options.mba_budget = 0;
    let program = compile(&[function], [0x6d_u8; 32], options).expect("compile");
    let mut random = XorShift(0x0f0e_0d0c_0b0a_0908);
    for _ in 0..100_000 {
        let left = random.next() & 1 == 0;
        runner.run_one(if left { Class::Left } else { Class::Right }, || {
            std::hint::black_box(run_oblivious(
                &program,
                if left {
                    [7, 3, 0, 0, 0, 0]
                } else {
                    [3, 7, 0, 0, 0, 0]
                },
            ));
        });
    }
}

fn vm_constant_branch(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let code = [
        0x48, 0x39, 0xf7, 0x76, 0x07, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89, 0xf8,
        0x48, 0x29, 0xf0, 0xc3,
    ];
    let function = lift_function(&code, 0x1000).expect("lift");
    let mut options = CompileOptions::new();
    options.constant_time = true;
    options.mba_depth = 0;
    options.mba_budget = 0;
    let program = compile(&[function], [0x6d_u8; 32], options).expect("compile");
    let mut random = XorShift(0x0f0e_0d0c_0b0a_0908);
    for _ in 0..100_000 {
        let left = random.next() & 1 == 0;
        runner.run_one(if left { Class::Left } else { Class::Right }, || {
            std::hint::black_box(run_oblivious(
                &program,
                if left {
                    [9, 4, 0, 0, 0, 0]
                } else {
                    [4, 9, 0, 0, 0, 0]
                },
            ));
        });
    }
}

fn vm_constant_memory(runner: &mut CtRunner, _rng: &mut BenchRng) {
    // mov [rdi], sil; mov al, [rdi]; ret
    let code = [0x40, 0x88, 0x37, 0x8a, 0x07, 0xc3];
    let function = lift_function(&code, 0x1000).expect("lift");
    let mut options = CompileOptions::new();
    options.constant_time = true;
    options.mba_depth = 0;
    options.mba_budget = 0;
    let program = compile(&[function], [0x6d_u8; 32], options).expect("compile");
    let mut random = XorShift(0x0f0e_0d0c_0b0a_0908);
    for _ in 0..20_000 {
        let left = random.next() & 1 == 0;
        runner.run_one(if left { Class::Left } else { Class::Right }, || {
            std::hint::black_box(run_oblivious(
                &program,
                if left {
                    [0x100, 0x11, 0, 0, 0, 0]
                } else {
                    [0x200, 0x22, 0, 0, 0, 0]
                },
            ));
        });
    }
}

fn vm_constant_loop(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let code = [
        0x31, 0xc0, 0x48, 0x85, 0xf6, 0x74, 0x08, 0x48, 0x01, 0xf8, 0x48, 0xff, 0xce, 0x75, 0xf8,
        0xc3,
    ];
    let function = lift_function(&code, 0x1000).expect("lift");
    let mut options = CompileOptions::new();
    options.constant_time = true;
    options.constant_time_passes = 32;
    options.mba_depth = 0;
    options.mba_budget = 0;
    let program = compile(&[function], [0x6d_u8; 32], options).expect("compile");
    let mut random = XorShift(0x0f0e_0d0c_0b0a_0908);
    for _ in 0..100_000 {
        let left = random.next() & 1 == 0;
        runner.run_one(if left { Class::Left } else { Class::Right }, || {
            std::hint::black_box(run_oblivious(
                &program,
                if left {
                    [7, 7, 0, 0, 0, 0]
                } else {
                    [7, 0, 0, 0, 0, 0]
                },
            ));
        });
    }
}

ctbench_main!(
    crypto,
    crypto_same,
    vm,
    vm_constant,
    vm_constant_branch,
    vm_constant_loop,
    vm_constant_memory
);
