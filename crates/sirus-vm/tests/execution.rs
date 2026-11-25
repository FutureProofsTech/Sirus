//! End-to-end compiler/runtime execution tests inside the zero-dependency
//! workspace. These prove that lifter, MBA, encoder, manifest, cipher, and VM
//! agree before any binary injection is involved.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    reason = "integration test uses assertion panics, fixed vectors, and fixed-offset fixtures"
)]

use sirus_core::lifter::lift_function;
use sirus_core::program::{CompileOptions, CompiledProgram, compile};
use sirus_vm::engine::{Run, Status, VmInput, execute, execute_entry, execute_oblivious};

const fn options() -> CompileOptions {
    let mut options = CompileOptions::new();
    options.decoys = 2;
    options
}

fn compile_code(code: &[u8], seed: u8, options: CompileOptions) -> CompiledProgram {
    let function = match lift_function(code, 0x1000) {
        Ok(function) => function,
        Err(error) => panic!("lift failed: {error}"),
    };
    match compile(&[function], [seed; 32], options) {
        Ok(program) => program,
        Err(error) => panic!("compile failed: {error}"),
    }
}

fn run(program: &CompiledProgram, args: [u64; 6]) -> (u64, Status) {
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
    (result.value, result.status)
}

fn run_oblivious(program: &CompiledProgram, args: [u64; 6], passes: usize) -> Run {
    execute_oblivious(
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
        passes,
    )
}

#[test]
fn executes_straight_line_add() {
    let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
    let program = compile_code(&code, 0x11, options());
    let (value, status) = run(&program, [7, 5, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 12);
    let (value, status) = run(&program, [0, 0, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 0);
}

#[test]
fn executes_both_branches() {
    let code = [
        0x48, 0x39, 0xf7, 0x76, 0x07, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89, 0xf8,
        0x48, 0x29, 0xf0, 0xc3,
    ];
    let program = compile_code(&code, 0x22, options());
    let (value, status) = run(&program, [9, 4, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 13);
    let (value, status) = run(&program, [4, 9, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, u64::MAX - 4);
}

#[test]
fn executes_loop_with_dec_flags() {
    let code = [
        0x31, 0xc0, 0x48, 0x85, 0xf6, 0x74, 0x08, 0x48, 0x01, 0xf8, 0x48, 0xff, 0xce, 0x75, 0xf8,
        0xc3,
    ];
    let program = compile_code(&code, 0x33, options());
    let (value, status) = run(&program, [7, 5, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 35);
    let (value, status) = run(&program, [7, 0, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 0);
}

#[test]
fn executes_decoys_inserted_after_unconditional_jump() {
    let code = [0xeb, 0x00, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
    let mut decoy_options = options();
    decoy_options.decoys = 1;
    let program = compile_code(&code, 0x44, decoy_options);
    assert!(program.stats().decoy_blocks >= 2);
    let (value, status) = run(&program, [11, 31, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 42);
}

#[test]
fn executes_branchy_oblivious_with_fixed_steps() {
    let code = [
        0x48, 0x39, 0xf7, 0x76, 0x07, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89, 0xf8,
        0x48, 0x29, 0xf0, 0xc3,
    ];
    let mut options = options();
    options.constant_time = true;
    options.mba_depth = 0;
    options.mba_budget = 0;
    let program = compile_code(&code, 0x66, options);
    let passes = usize::from(program.constant_time_passes());
    let left = run_oblivious(&program, [9, 4, 0, 0, 0, 0], passes);
    let right = run_oblivious(&program, [4, 9, 0, 0, 0, 0], passes);
    assert_eq!(left.status, Status::Returned);
    assert_eq!(right.status, Status::Returned);
    assert_eq!(left.value, 13);
    assert_eq!(right.value, u64::MAX - 4);
    assert_eq!(left.steps, right.steps);
    assert_eq!(run(&program, [9, 4, 0, 0, 0, 0]), (13, Status::Returned));
}

#[test]
fn executes_loop_oblivious_with_fixed_steps() {
    let code = [
        0x31, 0xc0, 0x48, 0x85, 0xf6, 0x74, 0x08, 0x48, 0x01, 0xf8, 0x48, 0xff, 0xce, 0x75, 0xf8,
        0xc3,
    ];
    let mut options = options();
    options.constant_time = true;
    options.constant_time_passes = 32;
    options.mba_depth = 0;
    options.mba_budget = 0;
    let program = compile_code(&code, 0x77, options);
    let passes = usize::from(program.constant_time_passes());
    let many = run_oblivious(&program, [7, 5, 0, 0, 0, 0], passes);
    let none = run_oblivious(&program, [7, 0, 0, 0, 0, 0], passes);
    assert_eq!(many.status, Status::Returned);
    assert_eq!(none.status, Status::Returned);
    assert_eq!(many.value, 35);
    assert_eq!(none.value, 0);
    assert_eq!(many.steps, none.steps);
    let bound = run_oblivious(&program, [7, 500, 0, 0, 0, 0], 4);
    assert_eq!(bound.status, Status::LoopBound);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "oblivious full-stack scan is intentionally slow under Miri"
)]
fn oblivious_runtime_supports_private_memory() {
    // mov [rdi], rsi; mov rax, [rdi]; ret
    let code = [0x48, 0x89, 0x37, 0x48, 0x8b, 0x07, 0xc3];
    let mut options = options();
    options.constant_time = true;
    options.mba_depth = 0;
    options.mba_budget = 0;
    let program = compile_code(&code, 0x88, options);
    let passes = usize::from(program.constant_time_passes());
    let first = run_oblivious(&program, [0x100, 0x1122_3344_5566_7788, 0, 0, 0, 0], passes);
    let second = run_oblivious(&program, [0x200, 0x99aa_bbcc_ddee_ff00, 0, 0, 0, 0], passes);
    assert_eq!(first.status, Status::Returned);
    assert_eq!(second.status, Status::Returned);
    assert_eq!(first.value, 0x1122_3344_5566_7788);
    assert_eq!(second.value, 0x99aa_bbcc_ddee_ff00);
    assert_eq!(first.steps, second.steps);
    let invalid = run_oblivious(&program, [u64::MAX, 1, 0, 0, 0, 0], passes);
    assert_eq!(invalid.status, Status::BadPayload);
}

#[test]
fn oblivious_entry_and_pass_errors_fail_closed() {
    let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
    let mut options = options();
    options.constant_time = true;
    let program = compile_code(&code, 0x99, options);
    let input = VmInput::new(
        program.payload(),
        program.seed(),
        program.expected_hash(),
        program.base_a(),
        program.base_b(),
        program.entry_states(),
        program.fuel(),
    );
    let tables = sirus_vm::shared::derive::Tables::derive(program.seed()).decode_tables();
    let wrong_entry = sirus_vm::engine::execute_oblivious_with_tables(input, 7, [0; 6], &tables, 4);
    assert_eq!(wrong_entry.status, Status::BadPayload);
    let zero_passes =
        sirus_vm::engine::execute_oblivious_with_tables(input, 0, [7, 5, 0, 0, 0, 0], &tables, 0);
    assert_eq!(zero_passes.status, Status::LoopBound);
    let normal = execute_entry(input, 0, [7, 5, 0, 0, 0, 0], &tables, false, 4);
    let constant = execute_entry(input, 0, [7, 5, 0, 0, 0, 0], &tables, true, 4);
    assert_eq!(normal.status, Status::Returned);
    assert_eq!(constant.status, Status::Returned);
    assert_eq!(normal.value, 12);
    assert_eq!(constant.value, 12);
}

#[test]
fn oblivious_tampered_payload_fails_closed() {
    let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
    let mut options = options();
    options.constant_time = true;
    let program = compile_code(&code, 0xaa, options);
    let mut tampered = [0_u8; 2048];
    let mut length = 0_usize;
    for byte in program.payload() {
        if let Some(slot) = tampered.get_mut(length) {
            *slot = *byte;
        }
        length += 1;
    }
    if let Some(slot) = tampered.get_mut(length.saturating_sub(1)) {
        *slot ^= 0x5a;
    }
    let result = execute_oblivious(
        VmInput::new(
            tampered.get(..length).unwrap_or(&[]),
            program.seed(),
            program.expected_hash(),
            program.base_a(),
            program.base_b(),
            program.entry_states(),
            program.fuel(),
        ),
        0,
        [7, 5, 0, 0, 0, 0],
        4,
    );
    assert_eq!(result.status, Status::BadPayload);
}

#[test]
fn tampering_corrupts_execution() {
    let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
    let program = compile_code(&code, 0x55, options());
    let original = program.payload();
    assert!(original.len() > 8);
    let mut tampered = [0_u8; 2048];
    let mut length = 0_usize;
    for byte in original {
        if let Some(slot) = tampered.get_mut(length) {
            *slot = *byte;
        }
        length += 1;
    }
    if let Some(byte) = tampered.get_mut(length / 2) {
        *byte ^= 0x80;
    }
    let payload = tampered.get(..length).unwrap_or(&[]);
    let result = execute(
        VmInput::new(
            payload,
            program.seed(),
            program.expected_hash(),
            program.base_a(),
            program.base_b(),
            program.entry_states(),
            program.fuel(),
        ),
        0,
        [3, 4, 0, 0, 0, 0],
    );
    assert!(
        result.status != Status::Returned || result.value != 7,
        "tampered payload produced a valid result"
    );
}

#[test]
fn fuel_exhaustion_is_deterministic() {
    let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
    let program = compile_code(&code, 0x66, options());
    let result = execute(
        VmInput::new(
            program.payload(),
            program.seed(),
            program.expected_hash(),
            program.base_a(),
            program.base_b(),
            program.entry_states(),
            1,
        ),
        0,
        [1, 2, 0, 0, 0, 0],
    );
    assert_eq!(result.status, Status::FuelExhausted);
}

const DEMO_CHECK: [u8; 43] = [
    0x48, 0x39, 0xf7, 0x76, 0x15, 0x48, 0x8d, 0x0c, 0x7f, 0x48, 0x01, 0xf1, 0x48, 0xb8, 0x78, 0x56,
    0x34, 0x12, 0x5a, 0x5a, 0xa5, 0xa5, 0x48, 0x31, 0xc8, 0xc3, 0x48, 0x31, 0xfe, 0x48, 0xb8, 0xf0,
    0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x48, 0x01, 0xf0, 0xc3,
];

const DEMO_LOOP: [u8; 139] = [
    0x48, 0xb8, 0x15, 0x7c, 0x4a, 0x7f, 0xb9, 0x79, 0x37, 0x9e, 0x48, 0x0f, 0xaf, 0xc7, 0x48, 0x83,
    0xe6, 0x07, 0x74, 0x76, 0x48, 0xc1, 0xc0, 0x05, 0x48, 0x31, 0xf8, 0x83, 0xfe, 0x01, 0x74, 0x6a,
    0x48, 0x89, 0xc1, 0x48, 0xc1, 0xc1, 0x05, 0x48, 0x8d, 0x47, 0x01, 0x48, 0x31, 0xc8, 0x83, 0xfe,
    0x02, 0x74, 0x57, 0x48, 0x89, 0xc1, 0x48, 0xc1, 0xc1, 0x05, 0x48, 0x8d, 0x47, 0x02, 0x48, 0x31,
    0xc8, 0x83, 0xfe, 0x03, 0x74, 0x44, 0x48, 0x89, 0xc1, 0x48, 0xc1, 0xc1, 0x05, 0x48, 0x8d, 0x47,
    0x03, 0x48, 0x31, 0xc8, 0x83, 0xfe, 0x04, 0x74, 0x31, 0x48, 0x89, 0xc1, 0x48, 0xc1, 0xc1, 0x05,
    0x48, 0x8d, 0x47, 0x04, 0x48, 0x31, 0xc8, 0x83, 0xfe, 0x05, 0x74, 0x1e, 0x48, 0x89, 0xc1, 0x48,
    0xc1, 0xc1, 0x05, 0x48, 0x8d, 0x47, 0x05, 0x48, 0x31, 0xc8, 0x83, 0xfe, 0x06, 0x74, 0x0b, 0x48,
    0xc1, 0xc0, 0x05, 0x48, 0x83, 0xc7, 0x06, 0x48, 0x31, 0xf8, 0xc3,
];

const fn reference_check(a: u64, b: u64) -> u64 {
    if a > b {
        a.wrapping_mul(3).wrapping_add(b) ^ 0xa5a5_5a5a_1234_5678
    } else {
        (b ^ a).wrapping_add(0x1234_5678_9abc_def0)
    }
}

const fn reference_loop(a: u64, b: u64) -> u64 {
    let mut accumulator = a.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut index = 0_u64;
    let limit = b & 7;
    while index < limit {
        accumulator = accumulator.rotate_left(5) ^ a.wrapping_add(index);
        index = index.wrapping_add(1);
    }
    accumulator
}

#[test]
fn executes_real_rust_compiled_branch_function() {
    let program = compile_code(&DEMO_CHECK, 0x77, options());
    for (a, b) in [
        (7, 3),
        (3, 7),
        (0, 0),
        (u64::MAX, 0),
        (0, u64::MAX),
        (0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321),
    ] {
        let (value, status) = run(&program, [a, b, 0, 0, 0, 0]);
        assert_eq!(status, Status::Returned, "a={a} b={b}");
        assert_eq!(value, reference_check(a, b), "a={a} b={b}");
    }
}

#[test]
fn executes_real_rust_compiled_loop_function() {
    let program = compile_code(&DEMO_LOOP, 0x88, options());
    for (a, b) in [
        (7, 3),
        (1, 0),
        (0, 7),
        (0xdead_beef_cafe_babe, 5),
        (u64::MAX, 9),
    ] {
        let (value, status) = run(&program, [a, b, 0, 0, 0, 0]);
        assert_eq!(status, Status::Returned, "a={a} b={b}");
        assert_eq!(value, reference_loop(a, b), "a={a} b={b}");
    }
}

#[test]
fn multiple_functions_share_one_payload_and_engine() {
    let check = lift_function(&DEMO_CHECK, 0x3000).expect("check");
    let looping = lift_function(&DEMO_LOOP, 0x4000).expect("loop");
    let program = compile(&[check, looping], [0x99_u8; 32], options()).expect("compile");
    assert_eq!(program.entry_states().len(), 2);
    assert_eq!(program.stats().functions, 2);
    for index in 0..2_usize {
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
            index,
            [13, 5, 0, 0, 0, 0],
        );
        assert_eq!(result.status, Status::Returned, "entry {index}");
        let expected = if index == 0 {
            reference_check(13, 5)
        } else {
            reference_loop(13, 5)
        };
        assert_eq!(result.value, expected, "entry {index}");
    }
}

#[test]
fn constant_time_raises_fuel_for_multiple_entries() {
    let check = lift_function(&DEMO_CHECK, 0x3000).expect("check");
    let looping = lift_function(&DEMO_LOOP, 0x4000).expect("loop");
    let straight =
        lift_function(&[0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3], 0x5000).expect("straight");
    let mut options = options();
    options.constant_time = true;
    options.fuel = 1;
    options.mba_depth = 0;
    options.mba_budget = 0;
    let program = compile(&[check, looping, straight], [0x5a_u8; 32], options).expect("compile");
    assert!(program.fuel() > 1);
    let passes = usize::from(program.constant_time_passes());
    for index in 0..3_usize {
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
            index,
            [13, 5, 0, 0, 0, 0],
            passes,
        );
        assert_eq!(result.status, Status::Returned, "entry {index}");
    }
}

#[test]
fn executes_private_virtual_stack_memory() {
    // sub rsp,16; mov [rsp],rdi; mov [rsp+8],rsi; mov rax,[rsp];
    // add rax,[rsp+8]; add rsp,16; ret
    let code = [
        0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0x3c, 0x24, 0x48, 0x89, 0x74, 0x24, 0x08, 0x48, 0x8b,
        0x04, 0x24, 0x48, 0x03, 0x44, 0x24, 0x08, 0x48, 0x83, 0xc4, 0x10, 0xc3,
    ];
    let program = compile_code(&code, 0xaa, options());
    let (value, status) = run(&program, [0xdead_beef, 0x1234_5678, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 0xdead_beef_u64.wrapping_add(0x1234_5678));
}

#[test]
fn executes_push_and_pop() {
    // push rdi; push rsi; pop rax; pop rcx; add rax,rcx; ret
    let code = [0x57, 0x56, 0x58, 0x59, 0x48, 0x01, 0xc8, 0xc3];
    let program = compile_code(&code, 0xbb, options());
    let (value, status) = run(&program, [u64::MAX, 2, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 1);
}

#[test]
fn executes_conditional_move() {
    // mov rax,rdi; cmp rdi,rsi; cmovg rax,rsi; ret
    let code = [
        0x48, 0x89, 0xf8, 0x48, 0x39, 0xf7, 0x48, 0x0f, 0x4f, 0xc6, 0xc3,
    ];
    let program = compile_code(&code, 0xcc, options());
    let (value, status) = run(&program, [9, 4, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 4);
    let (value, status) = run(&program, [4, 9, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 4);
}

#[test]
fn executes_setcc_and_signed_compare() {
    // xor eax,eax; cmp edi,esi; setl al; movzx eax,al; ret
    let code = [
        0x31, 0xc0, 0x39, 0xf7, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3,
    ];
    let program = compile_code(&code, 0xdd, options());
    let (value, status) = run(&program, [u64::MAX, 0, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 1);
    let (value, status) = run(&program, [0, u64::MAX, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 0);
}

#[test]
fn executes_32_bit_zero_extension() {
    // mov eax,edi; add eax,esi; ret
    let code = [0x89, 0xf8, 0x01, 0xf0, 0xc3];
    let program = compile_code(&code, 0xee, options());
    let (value, status) = run(&program, [0xffff_ffff, 1, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 0);
    let (value, status) = run(&program, [0x1234_5678, 0x1111_1111, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 0x2345_6789);
}

#[test]
fn executes_variable_shift_by_cl() {
    // mov rax,rdi; mov rcx,rsi; shl rax,cl; ret
    let code = [0x48, 0x89, 0xf8, 0x48, 0x89, 0xf1, 0x48, 0xd3, 0xe0, 0xc3];
    let program = compile_code(&code, 0xff, options());
    let (value, status) = run(&program, [1, 65, 0, 0, 0, 0]);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 2);
}
