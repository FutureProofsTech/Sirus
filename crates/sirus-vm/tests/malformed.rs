//! Hand-built payloads for fail-closed VM error paths.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::large_stack_arrays,
    reason = "test fixtures use assertion panics and fixed byte offsets"
)]

use sirus_vm::engine::{Status, VmInput, execute};
use sirus_vm::shared::cipher::{
    BodyCipher, base_key, encode_manifest_u32, encode_manifest_u64, manifest_byte, payload_hash,
};
use sirus_vm::shared::derive::Tables;
use sirus_vm::shared::format::{
    MAX_OPERANDS, REG_RAX, REG_RBX, ROLE_IMM, ROLE_REG, SEM_JMP, SEM_MOV_RI, SEM_RET, SEM_TRAP,
    format,
};

const SEED: [u8; 32] = [0x42; 32];
const STATE: u64 = 0x1234_5678_9abc_def0;

fn encode_instruction(tables: &Tables, semantic: u8, operands: [u64; MAX_OPERANDS]) -> Vec<u8> {
    let alias = tables.alias_for(semantic, 0).expect("alias");
    let layout = format(semantic).expect("layout");
    let mut bytes = Vec::new();
    bytes.push(alias.opcode);
    let mut position = 0_usize;
    while position < usize::from(layout.len) {
        let role = alias.order[position];
        let role_index = usize::from(role);
        let value = operands[role_index];
        match layout.roles[role_index] {
            ROLE_REG => {
                let logical = u8::try_from(value).expect("register");
                let encoded = tables
                    .encode_register(alias.reg_map, logical)
                    .expect("encoded register");
                bytes.push(encoded);
            }
            ROLE_IMM => {
                let encoded = if alias.big_endian {
                    value.to_be_bytes()
                } else {
                    value.to_le_bytes()
                };
                bytes.extend_from_slice(&encoded);
            }
            _ => panic!("invalid role"),
        }
        position += 1;
    }
    bytes
}

struct Fixture {
    payload: Vec<u8>,
    expected_hash: u64,
    base: u64,
    states: [[u64; 2]; 1],
}

fn make_fixture(body: &[u8], body_offset: Option<u32>, body_length: Option<u32>) -> Fixture {
    let tables = Tables::derive(&SEED);
    let key = base_key(&SEED);
    let offset = body_offset.unwrap_or(24);
    let length = body_length.unwrap_or_else(|| u32::try_from(body.len()).expect("length"));
    let mut payload = Vec::new();
    let count = encode_manifest_u64(1, tables.manifest_big_endian);
    for (index, byte) in count.iter().enumerate() {
        payload.push(manifest_byte(key, index, *byte));
    }
    let state = encode_manifest_u64(STATE, tables.manifest_big_endian);
    let mut field = [0_u8; 16];
    field[0..8].copy_from_slice(&state);
    field[8..12].copy_from_slice(&encode_manifest_u32(offset, tables.manifest_big_endian));
    field[12..16].copy_from_slice(&encode_manifest_u32(length, tables.manifest_big_endian));
    for (index, byte) in field.iter().enumerate() {
        payload.push(manifest_byte(key, 8 + index, *byte));
    }
    let mut cipher = BodyCipher::new(key, STATE, 24);
    let mut previous = 0_u8;
    for (position, plain) in (24_usize..).zip(body.iter()) {
        payload.push(cipher.apply(position, previous, *plain));
        previous = *plain;
    }
    let expected_hash = payload_hash(&SEED, &payload);
    Fixture {
        payload,
        expected_hash,
        base: key,
        states: [[STATE, 0]],
    }
}

fn run(fixture: &Fixture, fuel: u64) -> (u64, Status, u64) {
    let result = execute(
        VmInput::new(
            &fixture.payload,
            &SEED,
            fixture.expected_hash,
            fixture.base,
            0,
            &fixture.states,
            fuel,
        ),
        0,
        [0; 6],
    );
    (result.value, result.status, result.steps)
}

#[test]
fn handcrafted_return_and_move_execute() {
    let tables = Tables::derive(&SEED);
    let ret = encode_instruction(&tables, SEM_RET, [u64::from(REG_RAX), 0, 0, 0]);
    let fixture = make_fixture(&ret, None, None);
    let (_, status, _) = run(&fixture, 1000);
    assert_eq!(status, Status::Returned);

    let mut body = encode_instruction(&tables, SEM_MOV_RI, [u64::from(REG_RAX), 7, 0, 0]);
    body.extend_from_slice(&ret);
    let fixture = make_fixture(&body, None, None);
    let (value, status, _) = run(&fixture, 1000);
    assert_eq!(status, Status::Returned);
    assert_eq!(value, 7);
}

#[test]
fn invalid_opcode_and_register_fail_closed() {
    let mut body = encode_instruction(
        &Tables::derive(&SEED),
        SEM_RET,
        [u64::from(REG_RAX), 0, 0, 0],
    );
    body[0] = 0xfe;
    let fixture = make_fixture(&body, None, None);
    let (_, status, _) = run(&fixture, 1000);
    assert_eq!(status, Status::BadPayload);

    let mut body = encode_instruction(
        &Tables::derive(&SEED),
        SEM_RET,
        [u64::from(REG_RAX), 0, 0, 0],
    );
    body[1] = 0xff;
    let fixture = make_fixture(&body, None, None);
    let (_, status, _) = run(&fixture, 1000);
    assert_eq!(status, Status::BadPayload);
}

#[test]
fn bad_manifest_ranges_fail_closed() {
    let tables = Tables::derive(&SEED);
    let ret = encode_instruction(&tables, SEM_RET, [u64::from(REG_RAX), 0, 0, 0]);
    for fixture in [
        make_fixture(&ret, Some(0), None),
        make_fixture(&ret, Some(24), Some(0)),
        make_fixture(&ret, Some(24), Some(1000)),
        make_fixture(&ret, Some(1000), Some(2)),
    ] {
        let (_, status, _) = run(&fixture, 1000);
        assert_eq!(status, Status::BadPayload);
    }
}

#[test]
fn truncated_manifest_and_body_fail_closed() {
    let tables = Tables::derive(&SEED);
    let ret = encode_instruction(&tables, SEM_RET, [u64::from(REG_RAX), 0, 0, 0]);
    let fixture = make_fixture(&ret, None, None);
    let mut truncated = fixture.payload.clone();
    truncated.truncate(16);
    let result = execute(
        VmInput::new(
            &truncated,
            &SEED,
            fixture.expected_hash,
            fixture.base,
            0,
            &fixture.states,
            1000,
        ),
        0,
        [0; 6],
    );
    assert_eq!(result.status, Status::BadPayload);

    let mut truncated = fixture.payload.clone();
    truncated.truncate(25);
    let result = execute(
        VmInput::new(
            &truncated,
            &SEED,
            fixture.expected_hash,
            fixture.base,
            0,
            &fixture.states,
            1000,
        ),
        0,
        [0; 6],
    );
    assert_eq!(result.status, Status::BadPayload);
}

#[test]
fn unknown_state_and_trap_are_distinct() {
    let tables = Tables::derive(&SEED);
    let trap = encode_instruction(&tables, SEM_TRAP, [0; 4]);
    let mut fixture = make_fixture(&trap, None, None);
    fixture.states[0] = [STATE ^ 1, 0];
    let (_, status, _) = run(&fixture, 1000);
    assert_eq!(status, Status::BadPayload);
    fixture.states[0] = [STATE, 0];
    let (_, status, _) = run(&fixture, 1000);
    assert_eq!(status, Status::Trap);
}

#[test]
fn jump_to_missing_state_fails_closed() {
    let tables = Tables::derive(&SEED);
    let jump = encode_instruction(&tables, SEM_JMP, [999, u64::from(REG_RBX), 0, 0]);
    let fixture = make_fixture(&jump, None, None);
    let (_, status, _) = run(&fixture, 1000);
    assert_eq!(status, Status::BadPayload);
}

#[test]
fn fuel_and_entry_index_are_bounded() {
    let tables = Tables::derive(&SEED);
    let ret = encode_instruction(&tables, SEM_RET, [u64::from(REG_RAX), 0, 0, 0]);
    let fixture = make_fixture(&ret, None, None);
    let (_, status, _) = run(&fixture, 1);
    assert_eq!(status, Status::FuelExhausted);
    let result = execute(
        VmInput::new(
            &fixture.payload,
            &SEED,
            fixture.expected_hash,
            fixture.base,
            0,
            &fixture.states,
            1000,
        ),
        1,
        [0; 6],
    );
    assert_eq!(result.status, Status::BadPayload);
}
