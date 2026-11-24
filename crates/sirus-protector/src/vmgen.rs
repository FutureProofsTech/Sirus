//! Freestanding VM source synthesis, linking, and blob validation.

use core::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::entropy::junk;
use sirus_binfmt::elf::{Elf64, PF_R, PF_W, PF_X, PT_LOAD, STT_FUNC, STT_OBJECT, SymbolEntry};
use sirus_binfmt::pe::Pe64;
use sirus_core::program::CompiledProgram;
use sirus_core::shared::derive::{Seed, Tables, table_key};

use crate::entropy::build_id;
use crate::error::{ProtectError, Result};

const SIP_SOURCE: &str = include_str!("../../sirus-core/src/shared/sip.rs");
const FORMAT_SOURCE: &str = include_str!("../../sirus-core/src/shared/format.rs");
const DERIVE_SOURCE: &str = include_str!("../../sirus-core/src/shared/derive.rs");
const CIPHER_SOURCE: &str = include_str!("../../sirus-core/src/shared/cipher.rs");
const ENGINE_SOURCE: &str = include_str!("../../sirus-vm/src/engine.rs");
const HARDENED_SOURCE: &str = include_str!("../../sirus-hardened/src/runtime.rs");

const PAGE_SIZE: u64 = 0x1000;

/// Extracted Win64 VM section image.
#[derive(Debug)]
pub struct WindowsVmBlob {
    /// Combined `.text`/`.rdata` bytes for one RX section.
    pub blob: Vec<u8>,
    /// One entry offset per function, relative to the combined section start.
    pub entry_offsets: Vec<usize>,
}

/// Linked, validated freestanding VM image.
#[derive(Debug)]
pub struct VmBlob {
    /// Exact loadable segment bytes.
    pub segment: Vec<u8>,
    /// Virtual address at which the segment was linked.
    pub vm_vaddr: u64,
    /// Offset of the encrypted payload within `segment`.
    pub payload_offset: usize,
    /// Payload length.
    pub payload_len: usize,
    /// One entry virtual address per protected function, in input order.
    pub entry_vas: Vec<u64>,
}

macro_rules! emit {
    ($destination:expr, $($arguments:tt)*) => {
        write!($destination, $($arguments)*)
            .map_err(|_| ProtectError::internal("source formatting"))?
    };
}

fn append_u8_array(source: &mut String, name: &str, bytes: &[u8]) -> Result<()> {
    emit!(
        source,
        "#[used]\nstatic {name}: [u8; {}] = [\n",
        bytes.len()
    );
    for (index, byte) in bytes.iter().enumerate() {
        if index % 16 == 0 {
            source.push_str("    ");
        }
        emit!(source, "0x{byte:02x},");
        if index % 16 == 15 || index + 1 == bytes.len() {
            source.push('\n');
        }
    }
    source.push_str("];\n");
    Ok(())
}

fn append_u64_pair_array(source: &mut String, name: &str, pairs: &[[u64; 2]]) -> Result<()> {
    emit!(source, "static {name}: [[u64; 2]; {}] = [\n", pairs.len());
    for pair in pairs {
        let [first, second] = *pair;
        emit!(source, "    [0x{first:016x}, 0x{second:016x}],\n");
    }
    source.push_str("];\n");
    Ok(())
}

fn append_padding_module(source: &mut String, id: &str, seed: &Seed) -> Result<()> {
    let material = junk(seed, 0x7061_6464_696e_6700, 256);
    let count = 8_usize.saturating_add(usize::from(material.first().copied().unwrap_or(0) & 7));
    emit!(source, "#[allow(dead_code)]\npub mod padding {{\n");
    let mut index = 0_usize;
    while index < count {
        let base = index.saturating_mul(9);
        let first = read_u64(&material, base);
        let second = read_u64(&material, base.saturating_add(8));
        let third = read_u64(&material, base.saturating_add(16));
        let rounds = 4_u64.saturating_add(u64::from(
            material.get(base.saturating_add(24)).copied().unwrap_or(0) & 7,
        ));
        let rotation = u32::from(material.get(base.saturating_add(25)).copied().unwrap_or(0) & 63);
        let function = format!("pad_{id}_{index}");
        let keep = format!("KEEP_PAD_{id}_{index}");
        emit!(
            source,
            "#[inline(never)]\npub extern \"C\" fn {function}(x: u64) -> u64 {{\n\
             \x20   let mut value = x.wrapping_add(0x{first:016x});\n\
             \x20   let mut round = 0_u64;\n\
             \x20   while round < {rounds}_u64 {{\n\
             \x20       value = value.wrapping_mul(0x{second:016x}).rotate_left({rotation});\n\
             \x20       value ^= 0x{third:016x};\n\
             \x20       round = round.wrapping_add(1);\n\
             \x20   }}\n\
             \x20   value\n\
             }}\n\
             #[cfg(not(target_os = \"windows\"))]\n\
             #[used]\n\
             static {keep}: extern \"C\" fn(u64) -> u64 = {function};\n\n"
        );
        index = index.saturating_add(1);
    }
    emit!(source, "}}\n\n");
    Ok(())
}

#[inline]
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    bytes
        .get(offset..offset.saturating_add(8))
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .map_or(0, u64::from_le_bytes)
}

fn layout_preamble(seed: &Seed, domain: u64, prefix: &str, condition: &str) -> String {
    let material = junk(seed, domain, 8);
    let mut state =
        u64::from_le_bytes(<[u8; 8]>::try_from(material.as_slice()).unwrap_or([0_u8; 8]));
    let count = 1_usize.saturating_add(usize::try_from(state & 7).unwrap_or(0));
    let mut text = String::new();
    let mut index = 0_usize;
    while index < count {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let first = state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let second = state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let third = state;
        let rotate = u32::try_from(second & 63).unwrap_or(0);
        let block = format!(
            "    let mut {prefix}{index}: u64 = 0x{first:016x};\n    if {condition} == 0x{second:016x} {{\n        {prefix}{index} = {prefix}{index}.wrapping_mul(0x{third:016x}).rotate_left({rotate});\n        core::hint::black_box({prefix}{index});\n    }}\n"
        );
        text.push_str(&block);
        index = index.saturating_add(1);
    }
    text
}

fn mutate_engine_layout(source: &str, seed: &Seed) -> Result<String> {
    let normalized = source.replace("\r\n", "\n");
    let mut result = permute_handler_layout(&normalized, seed)?;
    let functions = [
        ("pub fn execute_with_tables(", ") -> Run {", "input.fuel"),
        (
            "pub fn execute_oblivious_with_tables(",
            ") -> Run {",
            "input.fuel",
        ),
        (
            "fn execute_semantic_inner(",
            ") -> Option<Flow> {",
            "u64::from(decoded.semantic)",
        ),
    ];
    let mut index = 0_usize;
    for (marker, signature, condition) in functions {
        let Some(start) = result.find(marker) else {
            return Err(ProtectError::internal("engine layout function missing"));
        };
        let Some(relative) = result.get(start..).and_then(|tail| tail.find(signature)) else {
            return Err(ProtectError::internal("engine layout signature missing"));
        };
        let insert = start
            .checked_add(relative)
            .and_then(|position| position.checked_add(signature.len()))
            .ok_or_else(|| ProtectError::internal("engine layout insertion"))?;
        let preamble = layout_preamble(
            seed,
            0x6c61_796f_7574_0001_u64.saturating_add(u64::try_from(index).unwrap_or(0)),
            &format!("_sirus_layout_{index}_"),
            condition,
        );
        result.insert_str(insert, &format!("\n{preamble}"));
        index = index.saturating_add(1);
    }
    Ok(result)
}

fn is_handler_arm_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    let indent = line.len().saturating_sub(trimmed.len());
    indent == 8 && (trimmed.starts_with("SEM_") || trimmed.starts_with("_ =>"))
}

/// Reorders top-level semantic match arms with a per-build permutation.
///
/// The runtime semantics are unchanged because the patterns are disjoint
/// constants. Moving handler bodies changes the generated code layout between
/// builds, which is the handler-layout mutation measured by the differential
/// gate.
fn permute_handler_layout(source: &str, seed: &Seed) -> Result<String> {
    let marker = "    match decoded.semantic {\n";
    let Some(start) = source.find(marker) else {
        return Err(ProtectError::internal("engine handler match missing"));
    };
    let body_start = start
        .checked_add(marker.len())
        .ok_or_else(|| ProtectError::internal("engine handler offset"))?;
    let bytes = source.as_bytes();
    let mut depth = 0_usize;
    let mut index = body_start;
    let mut close = None;
    while index < bytes.len() {
        match bytes.get(index).copied() {
            Some(b'{') => depth = depth.saturating_add(1),
            Some(b'}') if depth == 0 => {
                close = Some(index);
                break;
            }
            Some(b'}') => depth = depth.saturating_sub(1),
            _ => {}
        }
        index = index.saturating_add(1);
    }
    let close = close.ok_or_else(|| ProtectError::internal("engine handler match end"))?;
    let line_start = source
        .get(..close)
        .and_then(|prefix| prefix.rfind('\n'))
        .map_or(close, |position| position.saturating_add(1));
    let body = source
        .get(body_start..line_start)
        .ok_or_else(|| ProtectError::internal("engine handler body"))?;

    let mut arms = Vec::new();
    let mut current = String::new();
    let mut started = false;
    for line in body.split_inclusive('\n') {
        if is_handler_arm_line(line) {
            if started && !current.is_empty() {
                arms.push(core::mem::take(&mut current));
            }
            started = true;
        }
        if started {
            current.push_str(line);
        }
    }
    if !current.is_empty() {
        arms.push(current);
    }
    let mut wildcard = None;
    let mut handlers = Vec::with_capacity(arms.len());
    for arm in arms {
        if arm.trim_start().starts_with("_ =>") {
            wildcard = Some(arm);
        } else {
            handlers.push(arm);
        }
    }
    let Some(wildcard) = wildcard else {
        return Err(ProtectError::internal("engine wildcard handler missing"));
    };
    if handlers.len() < 2 {
        return Err(ProtectError::internal("engine handler inventory"));
    }
    let material = junk(seed, 0x6861_6e64_6c65_7200, 8);
    let mut state = u64::from_le_bytes(
        <[u8; 8]>::try_from(material.as_slice())
            .map_err(|_| ProtectError::internal("engine handler shuffle seed"))?,
    );
    let mut position = handlers.len().saturating_sub(1);
    while position > 0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let modulo = u64::try_from(position.saturating_add(1))
            .map_err(|_| ProtectError::internal("engine handler shuffle width"))?;
        let swap = usize::try_from(state % modulo)
            .map_err(|_| ProtectError::internal("engine handler shuffle index"))?;
        handlers.swap(position, swap);
        position = position.saturating_sub(1);
    }

    let mut replacement = String::from("\n");
    for arm in &handlers {
        replacement.push_str(arm);
    }
    replacement.push_str(&wildcard);
    let mut result = String::with_capacity(source.len());
    result.push_str(
        source
            .get(..body_start)
            .ok_or_else(|| ProtectError::internal("engine handler prefix"))?,
    );
    result.push_str(&replacement);
    result.push_str(
        source
            .get(line_start..)
            .ok_or_else(|| ProtectError::internal("engine handler suffix"))?,
    );
    Ok(result)
}

#[allow(
    clippy::too_many_lines,
    reason = "source generator is one linear code-emission transaction"
)]
fn generate_source(program: &CompiledProgram, id: &str, vm_base: u64) -> Result<String> {
    let payload_name = format!("SIRUS_PAYLOAD_{id}");
    let seed_name = format!("SIRUS_SEED_{id}");
    let states_name = format!("SIRUS_ENTRY_STATES_{id}");
    let table_name = format!("SIRUS_DECODE_TABLE_{id}");
    let table_key_name = format!("SIRUS_TABLE_KEY_{id}");
    let hash_name = format!("SIRUS_EXPECTED_HASH_{id}");
    let key_a_name = format!("SIRUS_BASE_A_{id}");
    let second_key_name = format!("SIRUS_BASE_B_{id}");
    let fuel_name = format!("SIRUS_FUEL_{id}");

    let mut source = String::with_capacity(
        program
            .payload()
            .len()
            .saturating_mul(6)
            .saturating_add(80_000),
    );
    let safety_attr = if program.hardened() {
        "#![allow(unsafe_code)]\n"
    } else {
        "#![forbid(unsafe_code)]\n"
    };
    emit!(
        source,
        "// Generated by Sirus. Unique build {id}.\n\
         #![no_std]\n#![no_main]\n{safety_attr}#![allow(dead_code)]\n#![allow(non_upper_case_globals)]\n#![allow(non_snake_case)]\n\n\
         use core::panic::PanicInfo;\n\n\
         #[panic_handler]\nfn panic(_info: &PanicInfo) -> ! {{\n    loop {{ core::hint::spin_loop(); }}\n}}\n\n\
"
    );
    emit!(source, "mod shared {{\n");
    emit!(source, "pub mod sip {{\n{SIP_SOURCE}\n}}\n");
    emit!(source, "pub mod format {{\n{FORMAT_SOURCE}\n}}\n");
    emit!(source, "pub mod derive {{\n{DERIVE_SOURCE}\n}}\n");
    emit!(source, "pub mod cipher {{\n{CIPHER_SOURCE}\n}}\n");
    emit!(source, "}}\n\n");
    append_padding_module(&mut source, id, program.seed())?;
    let engine_source = mutate_engine_layout(ENGINE_SOURCE, program.seed())?;
    emit!(source, "mod engine {{\n{engine_source}\n}}\n\n");
    if program.hardened() {
        emit!(source, "mod hardened {{\n{HARDENED_SOURCE}\n}}\n\n");
    }

    append_u8_array(&mut source, &payload_name, program.payload())?;
    append_u8_array(&mut source, &seed_name, program.seed())?;
    let tables = Tables::derive(program.seed());
    let decode_key = table_key(program.seed());
    let decode_bytes = tables.encode_runtime_table(decode_key);
    append_u8_array(&mut source, &table_name, &decode_bytes)?;
    emit!(
        source,
        "const {table_key_name}: u64 = 0x{decode_key:016x};\n"
    );
    append_u64_pair_array(&mut source, &states_name, program.entry_states())?;
    emit!(
        source,
        "const {hash_name}: u64 = 0x{:016x};\n\
         const {key_a_name}: u64 = 0x{:016x};\n\
         const {second_key_name}: u64 = 0x{:016x};\n\
         const {fuel_name}: u64 = {};\n\n",
        program.expected_hash(),
        program.base_a(),
        program.base_b(),
        program.fuel()
    );
    emit!(
        source,
        "const SIRUS_CONSTANT_TIME_{id}: bool = {};\n\
         const SIRUS_OBLIVIOUS_PASSES_{id}: usize = {};\n\n",
        program.constant_time(),
        program.constant_time_passes()
    );

    emit!(
        source,
        "#[inline]\nfn sirus_args(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> [u64; 6] {{\n\
         #[cfg(target_os = \"windows\")]\n\
         {{ let _ = (a4, a5); [0, 0, a1, a0, a2, a3] }}\n\
         #[cfg(not(target_os = \"windows\"))]\n\
         {{ [a0, a1, a2, a3, a4, a5] }}\n\
         }}\n\n"
    );
    let hardened_begin = if program.hardened() {
        "    hardened::lfence();\n    if hardened::debugger_present() { return 0; }\n    let _sirus_hardened_start = hardened::rdtsc();\n"
    } else {
        ""
    };
    let hardened_end = if program.hardened() {
        format!(
            "    hardened::lfence();\n    if !hardened::timing_ok(_sirus_hardened_start, 0x{:016x}) {{ return 0; }}\n",
            program.hardened_timing_cycles()
        )
    } else {
        String::new()
    };
    for (index, _) in program.entry_states().iter().enumerate() {
        let entry_name = format!("sirus_entry_{id}_{index}");
        let keep_name = format!("sirus_keep_{id}_{index}");
        let entry_layout = layout_preamble(
            program.seed(),
            0x656e_7472_7970_0001_u64.saturating_add(u64::try_from(index).unwrap_or(0)),
            &format!("_sirus_entry_layout_{index}_"),
            "a0",
        );
        emit!(
            source,
            "#[inline(never)]\n\
             pub extern \"C\" fn {entry_name}(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {{\n\
             {entry_layout}\
             {hardened_begin}\x20   let Some(tables) = shared::derive::DecodeTables::from_encrypted(\n\
             \x20       &{table_name},\n\
             \x20       {table_key_name},\n\
             \x20   ) else {{\n\
             \x20       return 0;\n\
             \x20   }};\n\
             \x20   let value = engine::execute_entry(\n\
             \x20       engine::VmInput::new(\n\
             \x20           &{payload_name},\n\
             \x20           &{seed_name},\n\
             \x20           {hash_name},\n\
             \x20           {key_a_name},\n\
             \x20           {second_key_name},\n\
             \x20           &{states_name},\n\
             \x20           {fuel_name},\n\
             \x20       ),\n\
             \x20       {index},\n\
             \x20       sirus_args(a0, a1, a2, a3, a4, a5),\n\
             \x20       &tables,\n\
             \x20       SIRUS_CONSTANT_TIME_{id},\n\
             \x20       SIRUS_OBLIVIOUS_PASSES_{id},\n\
             \x20   ).value;\n\
             {hardened_end}\x20   value\n\
             }}\n\n\
             #[cfg(not(target_os = \"windows\"))]\n\
             #[used]\n\
             static {keep_name}: extern \"C\" fn(u64, u64, u64, u64, u64, u64) -> u64 = {entry_name};\n\n"
        );
    }
    emit!(
        source,
        "const SIRUS_VM_BASE_{id}: u64 = 0x{vm_base:016x};\n"
    );
    Ok(source)
}

fn linker_script(vm_base: u64) -> String {
    format!(
        "PHDRS {{ sirus PT_LOAD FLAGS(5); }}\n\
         SECTIONS {{\n\
         \x20 . = 0x{vm_base:016x};\n\
         \x20 .sirus : {{ *(.text*) *(.rodata*) }} :sirus\n\
         \x20 /DISCARD/ : {{\n\
         \x20   *(.data*) *(.bss*) *(.eh_frame*) *(.eh_frame_hdr*)\n\
         \x20   *(.comment*) *(.note*) *(.got*) *(.got.plt*)\n\
         \x20   *(.data.rel.ro*) *(.rela*) *(.rel.*) *(.init_array*)\n\
         \x20   *(.fini_array*) *(.gcc_except_table*)\n\
         \x20 }}\n\
         }}\n"
    )
}

fn unique_temp_directory() -> Result<PathBuf> {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("sirus-vm-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path)
        .map_err(|error| ProtectError::io("create VM temporary directory", &error))?;
    Ok(path)
}

fn rustc_path() -> PathBuf {
    std::env::var_os("SIRUS_RUSTC").map_or_else(|| PathBuf::from("rustc"), PathBuf::from)
}

fn compile_source(source: &str, vm_base: u64, keep_temp: bool) -> Result<PathBuf> {
    let directory = unique_temp_directory()?;
    let source_path = directory.join("vm.rs");
    let script_path = directory.join("vm.ld");
    let output_path = directory.join("vm.elf");
    fs::write(&source_path, source)
        .map_err(|error| ProtectError::io("write generated VM source", &error))?;
    fs::write(&script_path, linker_script(vm_base))
        .map_err(|error| ProtectError::io("write linker script", &error))?;
    let linker_argument = format!("link-arg=-Wl,-T,{}", script_path.display());
    let output = Command::new(rustc_path())
        .arg("--edition=2021")
        .arg("--crate-type=bin")
        .arg("--crate-name")
        .arg("sirus_generated_vm")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("opt-level=z")
        .arg("-C")
        .arg("codegen-units=1")
        .arg("-C")
        .arg("debuginfo=0")
        .arg("-C")
        .arg("overflow-checks=off")
        .arg("-C")
        .arg("debug-assertions=off")
        .arg("-C")
        .arg("strip=none")
        .arg("-C")
        .arg("relocation-model=pic")
        .arg("-C")
        .arg("link-arg=-nostdlib")
        .arg("-C")
        .arg("link-arg=-static")
        .arg("-C")
        .arg("link-arg=-no-pie")
        .arg("-C")
        .arg("link-arg=-Wl,--build-id=none")
        .arg("-C")
        .arg("link-arg=-Wl,--no-gc-sections")
        .arg("-C")
        .arg("link-arg=-Wl,-e,0")
        .arg("-C")
        .arg(linker_argument)
        .arg("-o")
        .arg(&output_path)
        .arg(&source_path)
        .output()
        .map_err(|error| ProtectError::io("execute rustc", &error))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !keep_temp {
            drop(fs::remove_dir_all(&directory));
        }
        return Err(ProtectError::tool(format!(
            "rustc failed while building the VM blob:\n{stderr}"
        )));
    }
    Ok(output_path)
}

fn find_unique_symbol<'a>(
    elf: &Elf64<'a>,
    needle: &str,
    expected_kind: u8,
) -> Result<SymbolEntry<'a>> {
    let symbols = elf.find_symbols_containing(needle)?;
    let mut selected: Option<SymbolEntry<'a>> = None;
    for symbol in symbols {
        if symbol.kind == expected_kind && symbol.name.contains(needle) {
            if selected.is_some() {
                return Err(ProtectError::internal("duplicate generated VM symbol"));
            }
            selected = Some(symbol);
        }
    }
    selected
        .ok_or_else(|| ProtectError::internal(&format!("generated VM symbol missing: {needle}")))
}

#[allow(
    clippy::too_many_lines,
    reason = "blob validation is a linear sequence of fail-closed structural checks"
)]
fn validate_blob(blob: &[u8], program: &CompiledProgram, id: &str) -> Result<VmBlob> {
    let elf = Elf64::parse(blob)?;
    let mut load: Option<&sirus_binfmt::elf::ProgramHeader> = None;
    for header in elf.program_headers() {
        if header.p_type == PT_LOAD {
            if load.is_some() {
                return Err(ProtectError::internal(
                    "generated VM has multiple load segments",
                ));
            }
            load = Some(header);
        }
    }
    let load = load.ok_or_else(|| ProtectError::internal("generated VM has no load segment"))?;
    if (load.p_flags & PF_W) != 0 || (load.p_flags & PF_R) == 0 || (load.p_flags & PF_X) == 0 {
        return Err(ProtectError::internal(
            "generated VM segment is not read-execute",
        ));
    }
    if load.p_vaddr % PAGE_SIZE != 0 {
        return Err(ProtectError::internal(
            "generated VM segment is not page aligned",
        ));
    }
    let offset =
        usize::try_from(load.p_offset).map_err(|_| ProtectError::internal("VM segment offset"))?;
    let size =
        usize::try_from(load.p_filesz).map_err(|_| ProtectError::internal("VM segment size"))?;
    let segment = blob
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or_else(|| ProtectError::internal("VM range"))?,
        )
        .ok_or_else(|| ProtectError::internal("VM segment outside blob"))?
        .to_vec();
    let undefined = elf.undefined_symbols()?;
    if !undefined.is_empty() {
        return Err(ProtectError::tool(format!(
            "generated VM has undefined symbols: {undefined:?}"
        )));
    }
    if elf.has_relocations() {
        return Err(ProtectError::tool(
            "generated VM contains relocations; refusing non-relocatable blob",
        ));
    }
    let payload_name = format!("SIRUS_PAYLOAD_{id}");
    let payload_symbol = find_unique_symbol(&elf, &payload_name, STT_OBJECT)?;
    if payload_symbol.size != u64::try_from(program.payload().len()).unwrap_or(u64::MAX) {
        return Err(ProtectError::internal("payload symbol size mismatch"));
    }
    let payload_vaddr = payload_symbol.value;
    let payload_offset = payload_vaddr
        .checked_sub(load.p_vaddr)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| ProtectError::internal("payload outside VM segment"))?;
    let payload_len = usize::try_from(payload_symbol.size)
        .map_err(|_| ProtectError::internal("payload length"))?;
    if payload_offset
        .checked_add(payload_len)
        .is_none_or(|end| end > segment.len())
    {
        return Err(ProtectError::internal(
            "payload range outside segment bytes",
        ));
    }
    let seed_name = format!("SIRUS_SEED_{id}");
    let seed_symbol = find_unique_symbol(&elf, &seed_name, STT_OBJECT)?;
    let table_name = format!("SIRUS_DECODE_TABLE_{id}");
    let table_symbol = find_unique_symbol(&elf, &table_name, STT_OBJECT)?;
    if table_symbol.size
        != u64::try_from(sirus_core::shared::derive::RUNTIME_TABLE_BYTES).unwrap_or(0)
    {
        return Err(ProtectError::internal("decode table symbol size mismatch"));
    }
    if seed_symbol.size != 32 {
        return Err(ProtectError::internal("seed symbol size mismatch"));
    }
    let seed_offset = seed_symbol
        .value
        .checked_sub(load.p_vaddr)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| ProtectError::internal("seed outside VM segment"))?;
    let embedded_seed = segment
        .get(
            seed_offset
                ..seed_offset
                    .checked_add(32)
                    .ok_or_else(|| ProtectError::internal("seed range"))?,
        )
        .ok_or_else(|| ProtectError::internal("seed outside segment bytes"))?;
    if embedded_seed != program.seed() {
        return Err(ProtectError::internal(
            "embedded seed does not match compiler seed",
        ));
    }
    let mut entry_vas = Vec::with_capacity(program.entry_states().len());
    for index in 0..program.entry_states().len() {
        let needle = format!("sirus_entry_{id}_{index}");
        let symbol = find_unique_symbol(&elf, &needle, STT_FUNC)?;
        let address = symbol.value;
        let relative = address
            .checked_sub(load.p_vaddr)
            .ok_or_else(|| ProtectError::internal("entry outside VM segment"))?;
        let relative =
            usize::try_from(relative).map_err(|_| ProtectError::internal("entry offset"))?;
        if relative >= segment.len() {
            return Err(ProtectError::internal("entry outside segment bytes"));
        }
        entry_vas.push(address);
    }
    Ok(VmBlob {
        segment,
        vm_vaddr: load.p_vaddr,
        payload_offset,
        payload_len,
        entry_vas,
    })
}

/// Synthesizes, links, validates, and returns a freestanding VM image.
///
/// # Errors
///
/// Returns a typed error if source generation fails, `rustc` fails, or the
/// linked image contains writable/relocated/undefined/out-of-range material.
pub fn build_vm(program: &CompiledProgram, vm_base: u64, keep_temp: bool) -> Result<VmBlob> {
    let id = build_id(
        program.seed(),
        program.expected_hash(),
        program.payload().len(),
    );
    let source = generate_source(program, &id, vm_base)?;
    let blob_path = compile_source(&source, vm_base, keep_temp)?;
    let blob =
        fs::read(&blob_path).map_err(|error| ProtectError::io("read generated VM blob", &error))?;
    let result = validate_blob(&blob, program, &id);
    if !keep_temp {
        if let Some(parent) = blob_path.parent() {
            drop(fs::remove_dir_all(parent));
        }
    }
    result
}

fn read_le_u16(data: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| ProtectError::internal("COFF object offset"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| ProtectError::internal("COFF object bounds"))?;
    let array =
        <[u8; 2]>::try_from(bytes).map_err(|_| ProtectError::internal("COFF object width"))?;
    Ok(u16::from_le_bytes(array))
}

fn read_le_u32(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| ProtectError::internal("COFF object offset"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| ProtectError::internal("COFF object bounds"))?;
    let array =
        <[u8; 4]>::try_from(bytes).map_err(|_| ProtectError::internal("COFF object width"))?;
    Ok(u32::from_le_bytes(array))
}

fn coff_object_name(
    object: &[u8],
    entry: usize,
    string_table: usize,
    string_size: usize,
) -> Result<String> {
    let first = read_le_u32(object, entry)?;
    if first == 0 {
        let offset = usize::try_from(read_le_u32(object, entry.saturating_add(4))?)
            .map_err(|_| ProtectError::internal("COFF string offset"))?;
        if offset < 4 || offset >= string_size {
            return Err(ProtectError::internal("COFF string range"));
        }
        let start = string_table
            .checked_add(offset)
            .ok_or_else(|| ProtectError::internal("COFF string start"))?;
        let end = string_table
            .checked_add(string_size)
            .ok_or_else(|| ProtectError::internal("COFF string end"))?;
        let raw = object
            .get(start..end)
            .ok_or_else(|| ProtectError::internal("COFF string bytes"))?;
        let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        return String::from_utf8(raw.get(..length).unwrap_or(&[]).to_vec())
            .map_err(|_| ProtectError::internal("COFF string encoding"));
    }
    let raw = object
        .get(entry..entry.saturating_add(8))
        .ok_or_else(|| ProtectError::internal("COFF short name"))?;
    let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(raw.get(..length).unwrap_or(&[])).into_owned())
}

fn windows_entry_symbol(object: &[u8], id: &str, index: usize) -> Result<String> {
    let symbol_table = usize::try_from(read_le_u32(object, 8)?)
        .map_err(|_| ProtectError::internal("COFF symbol offset"))?;
    let symbol_count = usize::try_from(read_le_u32(object, 12)?)
        .map_err(|_| ProtectError::internal("COFF symbol count"))?;
    let strings = symbol_table
        .checked_add(
            symbol_count
                .checked_mul(18)
                .ok_or_else(|| ProtectError::internal("COFF symbol size"))?,
        )
        .ok_or_else(|| ProtectError::internal("COFF string table offset"))?;
    let string_size = usize::try_from(read_le_u32(object, strings)?)
        .map_err(|_| ProtectError::internal("COFF string table size"))?;
    let needle = format!("sirus_entry_{id}_{index}");
    let mut cursor = 0_usize;
    while cursor < symbol_count {
        let entry = symbol_table
            .checked_add(
                cursor
                    .checked_mul(18)
                    .ok_or_else(|| ProtectError::internal("COFF symbol offset"))?,
            )
            .ok_or_else(|| ProtectError::internal("COFF symbol entry"))?;
        let name = coff_object_name(object, entry, strings, string_size)?;
        let section = read_le_u16(object, entry.saturating_add(12))?;
        let kind = read_le_u16(object, entry.saturating_add(14))?;
        let aux = usize::from(
            object
                .get(entry.saturating_add(17))
                .copied()
                .ok_or_else(|| ProtectError::internal("COFF auxiliary count"))?,
        );
        if section > 0 && kind & 0x20 != 0 && name.contains(&needle) {
            return Ok(name);
        }
        cursor = cursor
            .checked_add(1)
            .and_then(|next| next.checked_add(aux))
            .ok_or_else(|| ProtectError::internal("COFF symbol cursor"))?;
    }
    Err(ProtectError::internal("Windows entry symbol missing"))
}

/// Builds a Win64 VM image for injection into a PE32+ host.
///
/// The object is linked as a no-import DLL, then its `.text` and `.rdata`
/// sections are copied into one contiguous RX blob. Entry offsets are taken
/// from the linker map, and relocations targeting extracted bytes are rejected.
///
/// # Errors
///
/// Returns a typed error if the Windows target, `rustc`, or `lld-link` is
/// unavailable, or if the resulting image is structurally invalid.
#[allow(
    clippy::too_many_lines,
    reason = "Windows toolchain orchestration is a linear external-process transaction"
)]
pub fn build_windows_vm(program: &CompiledProgram, keep_temp: bool) -> Result<WindowsVmBlob> {
    let id = build_id(
        program.seed(),
        program.expected_hash(),
        program.payload().len(),
    );
    let source = generate_source(program, &id, 0x1_8000_0000)?;
    let directory = unique_temp_directory()?;
    let source_path = directory.join("vm.rs");
    let object_path = directory.join("vm.o");
    let dll_path = directory.join("vm.dll");
    let map_path = directory.join("vm.map");
    let stub_path = directory.join("chkstk.s");
    let stub_object = directory.join("chkstk.o");
    let shim_path = directory.join("shim.s");
    let shim_object = directory.join("shim.o");
    fs::write(&source_path, source)
        .map_err(|error| ProtectError::io("write Windows VM source", &error))?;
    fs::write(
        &stub_path,
        ".text\n.globl ___chkstk_ms\n.def ___chkstk_ms; .scl 2; .type 32; .endef\n___chkstk_ms:\n    movq %rsp, %r10\n    subq %rax, %r10\n    andq $-4096, %r10\n1:\n    orq $0, (%r10)\n    addq $4096, %r10\n    cmpq %rsp, %r10\n    jb 1b\n    ret\n",
    )
    .map_err(|error| ProtectError::io("write Windows stack-probe stub", &error))?;
    let assembler = Command::new("x86_64-w64-mingw32-gcc")
        .arg("-c")
        .arg(&stub_path)
        .arg("-o")
        .arg(&stub_object)
        .output()
        .map_err(|error| ProtectError::io("execute Windows assembler", &error))?;
    if !assembler.status.success() {
        let stderr = String::from_utf8_lossy(&assembler.stderr);
        if !keep_temp {
            drop(fs::remove_dir_all(&directory));
        }
        return Err(ProtectError::tool(format!(
            "windows assembler failed:\n{stderr}"
        )));
    }
    let rustc = Command::new(rustc_path())
        .arg("--target")
        .arg("x86_64-pc-windows-gnu")
        .arg("--edition=2021")
        .arg("--crate-type=lib")
        .arg("--emit=obj")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("opt-level=z")
        .arg("-C")
        .arg("relocation-model=pic")
        .arg("-o")
        .arg(&object_path)
        .arg(&source_path)
        .output()
        .map_err(|error| ProtectError::io("execute Windows rustc", &error))?;
    if !rustc.status.success() {
        let stderr = String::from_utf8_lossy(&rustc.stderr);
        if !keep_temp {
            drop(fs::remove_dir_all(&directory));
        }
        return Err(ProtectError::tool(format!(
            "windows rustc failed:\n{stderr}"
        )));
    }
    let object = fs::read(&object_path)
        .map_err(|error| ProtectError::io("read Windows VM object", &error))?;
    let mut entry_symbols = Vec::with_capacity(program.entry_states().len());
    for index in 0..program.entry_states().len() {
        entry_symbols.push(windows_entry_symbol(&object, &id, index)?);
    }
    let mut shim_source = String::from(".text\n");
    for (index, symbol) in entry_symbols.iter().enumerate() {
        let shim = format!(
            ".globl sirus_shim_{id}_{index}\n.def sirus_shim_{id}_{index}; .scl 2; .type 32; .endef\nsirus_shim_{id}_{index}:\n    pushq %rcx\n    pushq %rdx\n    pushq %r8\n    pushq %r9\n    pushq %r10\n    pushq %r11\n    subq $136, %rsp\n    movdqu %xmm0, 32(%rsp)\n    movdqu %xmm1, 48(%rsp)\n    movdqu %xmm2, 64(%rsp)\n    movdqu %xmm3, 80(%rsp)\n    movdqu %xmm4, 96(%rsp)\n    movdqu %xmm5, 112(%rsp)\n    call {symbol}\n    movdqu 32(%rsp), %xmm0\n    movdqu 48(%rsp), %xmm1\n    movdqu 64(%rsp), %xmm2\n    movdqu 80(%rsp), %xmm3\n    movdqu 96(%rsp), %xmm4\n    movdqu 112(%rsp), %xmm5\n    addq $136, %rsp\n    popq %r11\n    popq %r10\n    popq %r9\n    popq %r8\n    popq %rdx\n    popq %rcx\n    ret\n"
        );
        shim_source.push_str(&shim);
    }
    fs::write(&shim_path, shim_source)
        .map_err(|error| ProtectError::io("write Windows ABI shim", &error))?;
    let shim_assembler = Command::new("x86_64-w64-mingw32-gcc")
        .arg("-c")
        .arg(&shim_path)
        .arg("-o")
        .arg(&shim_object)
        .output()
        .map_err(|error| ProtectError::io("execute Windows ABI assembler", &error))?;
    if !shim_assembler.status.success() {
        let stderr = String::from_utf8_lossy(&shim_assembler.stderr);
        if !keep_temp {
            drop(fs::remove_dir_all(&directory));
        }
        return Err(ProtectError::tool(format!(
            "windows ABI assembler failed:\n{stderr}"
        )));
    }
    let map_argument = format!("/map:{}", map_path.display());
    let output_argument = format!("/out:{}", dll_path.display());
    let link = Command::new("lld-link")
        .arg("/dll")
        .arg("/noentry")
        .arg("/nodefaultlib")
        .arg("/opt:noref")
        .arg(output_argument)
        .arg(map_argument)
        .arg(&object_path)
        .arg(&stub_object)
        .arg(&shim_object)
        .output()
        .map_err(|error| ProtectError::io("execute lld-link", &error))?;
    if !link.status.success() {
        let stderr = String::from_utf8_lossy(&link.stderr);
        if !keep_temp {
            drop(fs::remove_dir_all(&directory));
        }
        return Err(ProtectError::tool(format!(
            "windows link failed:\n{stderr}"
        )));
    }
    let image =
        fs::read(&dll_path).map_err(|error| ProtectError::io("read Windows VM image", &error))?;
    let pe = Pe64::parse(&image)?;
    let section_text = pe
        .sections()
        .iter()
        .find(|section| section.name_str() == Some(".text"))
        .copied()
        .ok_or_else(|| ProtectError::internal("Windows VM text section missing"))?;
    let section_rdata = pe
        .sections()
        .iter()
        .find(|section| section.name_str() == Some(".rdata"))
        .copied()
        .ok_or_else(|| ProtectError::internal("Windows VM rdata section missing"))?;
    let text = read_section(&image, section_text)?;
    let rdata = read_section(&image, section_rdata)?;
    let text_end = section_text
        .virtual_address
        .checked_add(section_text.virtual_size)
        .ok_or_else(|| ProtectError::internal("Windows VM text extent"))?;
    let rdata_end = section_rdata
        .virtual_address
        .checked_add(section_rdata.virtual_size)
        .ok_or_else(|| ProtectError::internal("Windows VM rdata extent"))?;
    validate_extracted_relocations(
        &image,
        &pe,
        [
            (section_text.virtual_address, text_end),
            (section_rdata.virtual_address, rdata_end),
        ],
    )?;
    let relative = section_rdata
        .virtual_address
        .checked_sub(section_text.virtual_address)
        .ok_or_else(|| ProtectError::internal("Windows VM section order"))?;
    let relative = usize::try_from(relative)
        .map_err(|_| ProtectError::internal("Windows VM section offset"))?;
    let total = relative
        .checked_add(rdata.len())
        .ok_or_else(|| ProtectError::internal("Windows VM size"))?;
    let mut blob = vec![0_u8; total];
    if let Some(destination) = blob.get_mut(..text.len()) {
        destination.copy_from_slice(text);
    }
    if let Some(destination) = blob.get_mut(relative..relative.saturating_add(rdata.len())) {
        destination.copy_from_slice(rdata);
    }
    let map_text = fs::read_to_string(&map_path)
        .map_err(|error| ProtectError::io("read Windows VM map", &error))?;
    let image_base = pe.optional_header().image_base;
    let mut entry_offsets = Vec::with_capacity(program.entry_states().len());
    for index in 0..program.entry_states().len() {
        let needle = format!("sirus_shim_{id}_{index}");
        let entry_address = map_text
            .lines()
            .find(|line| line.contains(&needle))
            .and_then(|line| {
                line.split_whitespace()
                    .find(|token| token.len() >= 16 && token.starts_with("00000001"))
            })
            .and_then(|token| u64::from_str_radix(token, 16).ok())
            .ok_or_else(|| ProtectError::internal("Windows VM entry symbol missing"))?;
        let entry_rva = entry_address
            .checked_sub(image_base)
            .ok_or_else(|| ProtectError::internal("Windows VM entry base"))?;
        let entry_offset = entry_rva
            .checked_sub(u64::from(section_text.virtual_address))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| ProtectError::internal("Windows VM entry offset"))?;
        if entry_offset >= text.len() {
            if !keep_temp {
                drop(fs::remove_dir_all(&directory));
            }
            return Err(ProtectError::internal("Windows VM entry outside text"));
        }
        entry_offsets.push(entry_offset);
    }
    if !keep_temp {
        drop(fs::remove_dir_all(&directory));
    }
    Ok(WindowsVmBlob {
        blob,
        entry_offsets,
    })
}

/// Rejects base relocations that would land in the extracted `.text`/`.rdata`
/// bytes, because the injected section does not register a relocation table.
fn validate_extracted_relocations(
    image: &[u8],
    pe: &Pe64<'_>,
    ranges: [(u32, u32); 2],
) -> Result<()> {
    let Some((_, section)) = pe.find_section(".reloc") else {
        return Ok(());
    };
    validate_relocation_ranges(read_section(image, section)?, ranges)
}

fn validate_relocation_ranges(raw: &[u8], ranges: [(u32, u32); 2]) -> Result<()> {
    let mut block = 0_usize;
    while block < raw.len() {
        let page = read_le_u32(raw, block)?;
        let size = usize::try_from(read_le_u32(
            raw,
            block
                .checked_add(4)
                .ok_or_else(|| ProtectError::internal("Windows VM relocation header"))?,
        )?)
        .map_err(|_| ProtectError::internal("Windows VM relocation block size"))?;
        if page == 0 && size == 0 {
            break;
        }
        if size < 8 {
            return Err(ProtectError::internal("Windows VM relocation block"));
        }
        let end = block
            .checked_add(size)
            .ok_or_else(|| ProtectError::internal("Windows VM relocation block end"))?;
        if end > raw.len() {
            return Err(ProtectError::internal("Windows VM relocation block bounds"));
        }
        let mut entry = block
            .checked_add(8)
            .ok_or_else(|| ProtectError::internal("Windows VM relocation entries"))?;
        while entry.checked_add(2).is_some_and(|stop| stop <= end) {
            let encoded = read_le_u16(raw, entry)?;
            let kind = encoded >> 12;
            let offset = u32::from(encoded & 0x0fff);
            let rva = page
                .checked_add(offset)
                .ok_or_else(|| ProtectError::internal("Windows VM relocation RVA"))?;
            if kind != 0
                && ranges
                    .iter()
                    .any(|(start, stop)| rva >= *start && rva < *stop)
            {
                return Err(ProtectError::internal(
                    "Windows VM has an unapplied relocation in extracted code",
                ));
            }
            entry = entry
                .checked_add(2)
                .ok_or_else(|| ProtectError::internal("Windows VM relocation step"))?;
        }
        block = end;
    }
    Ok(())
}

fn read_section(image: &[u8], section: sirus_binfmt::pe::Section) -> Result<&[u8]> {
    let start = usize::try_from(section.raw_offset)
        .map_err(|_| ProtectError::internal("Windows VM raw offset"))?;
    let size = usize::try_from(section.raw_size)
        .map_err(|_| ProtectError::internal("Windows VM raw size"))?;
    image
        .get(
            start
                ..start
                    .checked_add(size)
                    .ok_or_else(|| ProtectError::internal("Windows VM raw range"))?,
        )
        .ok_or_else(|| ProtectError::internal("Windows VM raw bytes"))
}

/// Exposes the generated source for audit/testing.
///
/// # Errors
///
/// Propagates source-formatting failures.
#[inline]
pub fn source_for_audit(program: &CompiledProgram, vm_base: u64) -> Result<String> {
    let id = build_id(
        program.seed(),
        program.expected_hash(),
        program.payload().len(),
    );
    generate_source(program, &id, vm_base)
}

/// Checks that a path exists and is a regular file.
#[inline]
pub fn ensure_readable(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(ProtectError::usage(format!(
            "input path is not a regular file: {}",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ENGINE_SOURCE, ensure_readable, permute_handler_layout, read_le_u16, read_le_u32,
        source_for_audit, validate_blob, validate_relocation_ranges, windows_entry_symbol,
    };
    use sirus_core::lifter::lift_function;
    use sirus_core::program::{CompileOptions, CompiledProgram, compile};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn program() -> CompiledProgram {
        let function = lift_function(&[0x48, 0x89, 0xf8, 0xc3], 0x1000).expect("lift");
        compile(&[function], [0x55_u8; 32], CompileOptions::new()).expect("compile")
    }

    #[test]
    fn generated_source_contains_runtime_and_symbols() {
        let program = program();
        let first = source_for_audit(&program, 0x10_000).expect("source");
        let second = source_for_audit(&program, 0x10_000).expect("source");
        assert_eq!(first, second);
        assert!(first.contains("#![forbid(unsafe_code)]"));
        assert!(first.contains("sirus_entry_"));
        assert!(first.contains("SIRUS_PAYLOAD_"));
        assert!(first.contains("SIRUS_DECODE_TABLE_"));
        assert!(first.contains("DecodeTables::from_encrypted"));
        assert!(first.contains("execute_with_tables"));
    }

    #[test]
    fn constant_time_source_uses_oblivious_entry() {
        let code = [
            0x48, 0x39, 0xf7, 0x76, 0x07, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89,
            0xf8, 0x48, 0x29, 0xf0, 0xc3,
        ];
        let function = lift_function(&code, 0x1000).expect("lift");
        let mut options = CompileOptions::new();
        options.constant_time = true;
        options.constant_time_passes = 64;
        let program = compile(&[function], [0x56_u8; 32], options).expect("compile");
        let source = source_for_audit(&program, 0x10_000).expect("source");
        assert!(source.contains("SIRUS_CONSTANT_TIME_"));
        assert!(source.contains("= true;"));
        assert!(source.contains("SIRUS_OBLIVIOUS_PASSES_"));
        assert!(source.contains("= 64;"));
        assert!(source.contains("execute_entry"));
    }

    #[test]
    fn handler_layout_permutation_is_deterministic_and_complete() {
        let source = "    match decoded.semantic {\n        SEM_A => 1,\n        SEM_B => 2,\n        SEM_C => 3,\n        _ => 0,\n    }\n";
        let seed = [0x31_u8; 32];
        let first = permute_handler_layout(source, &seed).expect("first");
        let second = permute_handler_layout(source, &seed).expect("second");
        assert_eq!(first, second);
        for name in ["SEM_A", "SEM_B", "SEM_C"] {
            assert_eq!(first.matches(name).count(), 1);
        }
        let wildcard = first.find("_ => 0").expect("wildcard");
        for name in ["SEM_A", "SEM_B", "SEM_C"] {
            assert!(first.find(name).expect("arm") < wildcard);
        }
        assert!(first.trim_end().ends_with('}'));
        let engine_first =
            permute_handler_layout(ENGINE_SOURCE, &[0x31_u8; 32]).expect("engine first");
        let engine_second =
            permute_handler_layout(ENGINE_SOURCE, &[0x31_u8; 32]).expect("engine second");
        assert_eq!(engine_first, engine_second);
        let alternate =
            permute_handler_layout(ENGINE_SOURCE, &[0x32_u8; 32]).expect("engine alternate");
        assert_ne!(engine_first, alternate);
    }

    #[test]
    fn handler_permutation_rejects_malformed_sources() {
        let seed = [0x33_u8; 32];
        assert!(permute_handler_layout("no match here", &seed).is_err());
        let no_wildcard =
            "    match decoded.semantic {\n        SEM_A => 1,\n        SEM_B => 2,\n    }\n";
        assert!(permute_handler_layout(no_wildcard, &seed).is_err());
        let one_handler =
            "    match decoded.semantic {\n        SEM_A => 1,\n        _ => 0,\n    }\n";
        assert!(permute_handler_layout(one_handler, &seed).is_err());
    }

    #[test]
    fn generated_layout_preambles_and_entry_dispatch_are_seeded() {
        let function = lift_function(&[0x48, 0x89, 0xf8, 0xc3], 0x1000).expect("lift");
        let first = compile(
            core::slice::from_ref(&function),
            [0x71_u8; 32],
            CompileOptions::new(),
        )
        .expect("first");
        let second = compile(
            core::slice::from_ref(&function),
            [0x72_u8; 32],
            CompileOptions::new(),
        )
        .expect("second");
        let source_a = source_for_audit(&first, 0x10_000).expect("source a");
        let source_b = source_for_audit(&second, 0x10_000).expect("source b");
        assert!(source_a.contains("_sirus_layout_0_"));
        assert!(source_a.contains("_sirus_entry_layout_0_"));
        assert!(source_a.contains("engine::execute_entry("));
        assert!(source_a.contains("SIRUS_CONSTANT_TIME_"));
        assert_ne!(source_a, source_b);
    }

    #[test]
    fn hardened_source_contains_unsafe_runtime_checks() {
        let function = lift_function(&[0x48, 0x89, 0xf8, 0xc3], 0x1000).expect("lift");
        let mut options = CompileOptions::new();
        options.hardened = true;
        options.hardened_timing_cycles = 42;
        let program =
            compile(core::slice::from_ref(&function), [0x73_u8; 32], options).expect("compile");
        let source = source_for_audit(&program, 0x10_000).expect("source");
        assert!(source.contains("#![allow(unsafe_code)]"));
        assert!(source.contains("mod hardened"));
        assert!(source.contains("debugger_present()"));
        assert!(source.contains("hardened::timing_ok"));
        assert!(source.contains("0x000000000000002a"));
    }

    #[test]
    fn coff_object_entry_symbol_is_parsed_without_nm() {
        let name = "sirus_entry_deadbeef_0";
        let symbol_table = 20_usize + 40;
        let strings = symbol_table + 18;
        let mut object = vec![0_u8; strings + 4 + name.len() + 1];
        object[0..2].copy_from_slice(&0x8664_u16.to_le_bytes());
        object[2..4].copy_from_slice(&1_u16.to_le_bytes());
        object[8..12].copy_from_slice(
            &u32::try_from(symbol_table)
                .expect("symbol table")
                .to_le_bytes(),
        );
        object[12..16].copy_from_slice(&1_u32.to_le_bytes());
        let entry = symbol_table;
        object[entry + 4..entry + 8].copy_from_slice(&4_u32.to_le_bytes());
        object[entry + 12..entry + 14].copy_from_slice(&1_u16.to_le_bytes());
        object[entry + 14..entry + 16].copy_from_slice(&0x20_u16.to_le_bytes());
        object[entry + 16] = 2;
        object[strings..strings + 4].copy_from_slice(
            &u32::try_from(4 + name.len() + 1)
                .expect("string size")
                .to_le_bytes(),
        );
        object[strings + 4..strings + 4 + name.len()].copy_from_slice(name.as_bytes());
        let symbol = windows_entry_symbol(&object, "deadbeef", 0).expect("symbol");
        assert_eq!(symbol, name);
        assert!(windows_entry_symbol(&object, "deadbeef", 1).is_err());
    }

    #[test]
    fn malformed_blobs_are_rejected() {
        let program = program();
        assert!(validate_blob(&[], &program, "deadbeef").is_err());
        assert!(validate_blob(b"not an elf", &program, "deadbeef").is_err());
    }

    #[test]
    fn readable_path_checks_are_explicit() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("sirus-readable-{}-{nanos}", std::process::id()));
        fs::write(&path, b"data").expect("write");
        assert!(ensure_readable(&path).is_ok());
        drop(fs::remove_file(&path));
        assert!(ensure_readable(&path).is_err());
        assert!(ensure_readable(&std::env::temp_dir()).is_err());
    }

    fn relocation_block(page: u32, entries: &[u16]) -> Vec<u8> {
        let size = 8 + entries.len() * 2;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&page.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        for entry in entries {
            bytes.extend_from_slice(&entry.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn relocation_parser_accepts_external_and_absolute_entries() {
        let mut raw = relocation_block(0xd000, &[0xaca0, 0xaca8]);
        raw.extend_from_slice(&[0_u8; 8]);
        assert!(validate_relocation_ranges(&raw, [(0x1000, 0x2000), (0x3000, 0x4000)]).is_ok());
        let absolute = relocation_block(0x1000, &[0x0010, 0x0020]);
        assert!(
            validate_relocation_ranges(&absolute, [(0x1000, 0x2000), (0x3000, 0x4000)]).is_ok()
        );
        assert!(validate_relocation_ranges(&[], [(0, 1), (2, 3)]).is_ok());
        assert!(validate_relocation_ranges(&[0_u8; 8], [(0, 1), (2, 3)]).is_ok());
    }

    #[test]
    fn relocation_parser_rejects_extracted_and_malformed_blocks() {
        let text = relocation_block(0x1000, &[0xa010]);
        assert!(validate_relocation_ranges(&text, [(0x1000, 0x2000), (0x3000, 0x4000)]).is_err());
        let rdata = relocation_block(0x3000, &[0xa008]);
        assert!(validate_relocation_ranges(&rdata, [(0x1000, 0x2000), (0x3000, 0x4000)]).is_err());

        assert!(validate_relocation_ranges(&[0_u8; 4], [(0, 1), (2, 3)]).is_err());
        let mut short = Vec::new();
        short.extend_from_slice(&0x1000_u32.to_le_bytes());
        short.extend_from_slice(&4_u32.to_le_bytes());
        assert!(validate_relocation_ranges(&short, [(0, 1), (2, 3)]).is_err());

        let mut oversized = Vec::new();
        oversized.extend_from_slice(&0x1000_u32.to_le_bytes());
        oversized.extend_from_slice(&0x100_u32.to_le_bytes());
        assert!(validate_relocation_ranges(&oversized, [(0, 1), (2, 3)]).is_err());
    }

    #[test]
    fn little_endian_relocation_reads_are_checked() {
        let bytes = [0x34_u8, 0x12, 0x78, 0x56];
        assert_eq!(read_le_u16(&bytes, 0).expect("u16"), 0x1234);
        assert_eq!(read_le_u32(&bytes, 0).expect("u32"), 0x5678_1234);
        assert!(read_le_u16(&bytes, 3).is_err());
        assert!(read_le_u32(&bytes, 1).is_err());
        assert!(read_le_u32(&bytes, usize::MAX).is_err());
    }
}
