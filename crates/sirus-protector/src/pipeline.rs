//! Protection pipeline and inspection output.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::Path;

use sirus_binfmt::elf::{
    Elf64, Injection, PF_X, PT_LOAD, SHF_WRITE, STT_OBJECT, inject, overwrite_vaddr,
    patch_relative_jump,
};
use sirus_binfmt::pe::{
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, Pe64,
    append_exception_table, append_executable_section as append_pe_section,
    patch_relative_jump_rva, refresh_checksum, write_data_directory,
};
use sirus_core::ir::MAX_FUNCTION_BYTES;
use sirus_core::lifter::{BinaryData, StackAbi, lift_function_with_data_and_calls};
use sirus_core::program::{ProgramStats, compile};
use sirus_core::shared::derive::Seed;

use crate::cli::{ProtectArgs, Selector};
use crate::entropy::{format_seed, junk, parse_seed, seed};
use crate::error::{ProtectError, Result};
use crate::vmgen;

#[derive(Clone, Debug)]
struct Target {
    name: String,
    va: u64,
    size: u64,
}

struct ElfReadOnly<'a> {
    elf: &'a Elf64<'a>,
}

impl BinaryData for ElfReadOnly<'_> {
    #[inline]
    fn read_readonly(&self, va: u64, len: usize) -> Option<&[u8]> {
        let size = u64::try_from(len).ok()?;
        let end = va.checked_add(size)?;
        let mut index = 0_usize;
        while index < self.elf.section_headers().len() {
            let section = self.elf.section_headers().get(index)?;
            let section_end = section.sh_addr.checked_add(section.sh_size)?;
            let contains = va >= section.sh_addr && end <= section_end;
            if contains {
                let writable = section.sh_flags & SHF_WRITE != 0;
                let relro = self
                    .elf
                    .section_name(index)
                    .is_some_and(|name| name.contains(".data.rel.ro"));
                if writable && !relro {
                    return None;
                }
                return self.elf.read_vaddr(va, size);
            }
            index = index.saturating_add(1);
        }
        None
    }
}

struct PeReadOnly<'a> {
    pe: &'a Pe64<'a>,
    image_base: u64,
}

impl BinaryData for PeReadOnly<'_> {
    #[inline]
    fn read_readonly(&self, va: u64, len: usize) -> Option<&[u8]> {
        let rva = u32::try_from(va.checked_sub(self.image_base)?).ok()?;
        let size = u32::try_from(len).ok()?;
        let section = self.pe.section_for_rva(rva, size)?;
        if section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            return None;
        }
        self.pe.read_rva(rva, size)
    }
}

/// Successful protection report.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ProtectReport {
    /// Number of protected functions.
    pub functions: usize,
    /// Build seed.
    pub seed: Seed,
    /// VM virtual base.
    pub vm_vaddr: u64,
    /// Encrypted payload size.
    pub payload_len: usize,
    /// VM segment size.
    pub vm_len: usize,
    /// Output file size.
    pub output_len: usize,
    /// Compiler statistics.
    pub stats: ProgramStats,
}

/// Resolves one selector to exactly one native target.
fn resolve_selector(elf: &Elf64<'_>, selector: &Selector) -> Result<Target> {
    match selector {
        Selector::Exact(name) => {
            let function = elf.find_function(name)?;
            Ok(Target {
                name: function.name.to_owned(),
                va: function.value,
                size: function.size,
            })
        }
        Selector::Contains(needle) => {
            let matches = elf.find_functions_containing(needle)?;
            if matches.is_empty() {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::NotFound));
            }
            if matches.len() > 1 {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::Ambiguous));
            }
            let Some(function) = matches.first() else {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::NotFound));
            };
            Ok(Target {
                name: function.name.to_owned(),
                va: function.value,
                size: function.size,
            })
        }
        Selector::Range { start, size } => Ok(Target {
            name: format!("range@{start:#x}"),
            va: *start,
            size: *size,
        }),
        Selector::Markers { begin, end } => {
            let begin_offset = elf.find_pattern_unique(begin)?;
            let end_offset = elf.find_pattern_unique(end)?;
            let begin =
                u64::try_from(begin_offset).map_err(|_| ProtectError::internal("marker offset"))?;
            let end =
                u64::try_from(end_offset).map_err(|_| ProtectError::internal("marker offset"))?;
            if end <= begin {
                return Err(ProtectError::usage(
                    "marker end must follow marker begin in the file",
                ));
            }
            let begin_va = elf.offset_to_vaddr(begin).ok_or(ProtectError::Format(
                sirus_binfmt::FormatError::RangeOutsideExecutable,
            ))?;
            let end_va = elf.offset_to_vaddr(end).ok_or(ProtectError::Format(
                sirus_binfmt::FormatError::RangeOutsideExecutable,
            ))?;
            if end_va <= begin_va {
                return Err(ProtectError::Format(
                    sirus_binfmt::FormatError::RangeOutsideExecutable,
                ));
            }
            Ok(Target {
                name: format!("markers@{begin_va:#x}"),
                va: begin_va,
                size: end_va - begin_va,
            })
        }
    }
}

const fn ranges_overlap(first_va: u64, first_size: u64, second_va: u64, second_size: u64) -> bool {
    let Some(first_end) = first_va.checked_add(first_size) else {
        return true;
    };
    let Some(second_end) = second_va.checked_add(second_size) else {
        return true;
    };
    first_va < second_end && second_va < first_end
}

fn validate_targets(elf: &Elf64<'_>, targets: &[Target]) -> Result<()> {
    for (index, target) in targets.iter().enumerate() {
        if target.size == 0 || target.size > u64::try_from(MAX_FUNCTION_BYTES).unwrap_or(u64::MAX) {
            return Err(ProtectError::Format(sirus_binfmt::FormatError::Unsupported));
        }
        let Some(segment) = elf.executable_segment(target.va, target.size) else {
            return Err(ProtectError::Format(
                sirus_binfmt::FormatError::RangeOutsideExecutable,
            ));
        };
        if (segment.p_flags & PF_X) == 0 {
            return Err(ProtectError::Format(
                sirus_binfmt::FormatError::RangeOutsideExecutable,
            ));
        }
        if elf.read_vaddr(target.va, target.size).is_none() {
            return Err(ProtectError::Format(sirus_binfmt::FormatError::Bounds));
        }
        for other in targets.iter().skip(index.saturating_add(1)) {
            if ranges_overlap(target.va, target.size, other.va, other.size) {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::Overlap));
            }
        }
    }
    let functions = elf.functions()?;
    for target in targets {
        for function in &functions {
            if function.value == target.va {
                continue;
            }
            if ranges_overlap(target.va, target.size, function.value, function.size) {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::Overlap));
            }
        }
    }
    let symbols = elf.symbols()?;
    for target in targets {
        for symbol in &symbols {
            if symbol.kind == STT_OBJECT
                && ranges_overlap(target.va, target.size, symbol.value, symbol.size)
            {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::Overlap));
            }
        }
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8], permissions: Option<fs::Permissions>) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("sirus-output"));
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(format!(".sirus-tmp.{}", std::process::id()));
    let temporary = parent.join(temporary_name);
    if let Err(error) = fs::write(&temporary, bytes) {
        drop(fs::remove_file(&temporary));
        return Err(ProtectError::io("write protected output", &error));
    }
    if let Some(permissions) = permissions {
        if let Err(error) = fs::set_permissions(&temporary, permissions) {
            drop(fs::remove_file(&temporary));
            return Err(ProtectError::io("set output permissions", &error));
        }
    }
    if let Err(error) = fs::rename(&temporary, path) {
        drop(fs::remove_file(&temporary));
        return Err(ProtectError::io("replace output file", &error));
    }
    Ok(())
}

/// Runs the protection pipeline.
///
/// # Errors
///
/// Propagates selector, lifting, compilation, VM linking, injection, patching,
/// and output errors with operation context.
#[allow(
    clippy::too_many_lines,
    clippy::large_stack_frames,
    reason = "top-level protection orchestration runs on the main thread and intentionally keeps compiler data on the stack"
)]
pub fn protect(arguments: &ProtectArgs) -> Result<ProtectReport> {
    vmgen::ensure_readable(&arguments.input)?;
    let input = fs::read(&arguments.input)
        .map_err(|error| ProtectError::io("read input executable", &error))?;
    if input.starts_with(b"MZ") {
        return protect_pe(arguments, &input);
    }
    let elf = Elf64::parse(&input)?;
    if elf.find_section(".sirus").is_some() {
        return Err(ProtectError::Format(
            sirus_binfmt::FormatError::AlreadyProtected,
        ));
    }
    let mut targets = Vec::with_capacity(arguments.selectors.len());
    for selector in &arguments.selectors {
        let target = resolve_selector(&elf, selector)?;
        targets.push(target);
    }
    validate_targets(&elf, &targets)?;

    let build_seed = if let Some(text) = &arguments.seed {
        parse_seed(text)?
    } else {
        seed()
    };
    let mut lifted = Vec::with_capacity(targets.len());
    let reader = ElfReadOnly { elf: &elf };
    let mut call_targets = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter().enumerate() {
        call_targets.push((
            target.va,
            u16::try_from(index).map_err(|_| ProtectError::internal("too many call targets"))?,
        ));
    }
    let mut data_base = 0_usize;
    for target in &targets {
        let code = elf
            .read_vaddr(target.va, target.size)
            .ok_or(ProtectError::Format(sirus_binfmt::FormatError::Bounds))?;
        let function = lift_function_with_data_and_calls(
            code,
            target.va,
            &reader,
            &call_targets,
            data_base,
            StackAbi::SYSTEM_V,
        )
        .map_err(|error| {
            ProtectError::context(format!("lift function {}", target.name), error.into())
        })?;
        data_base = data_base
            .checked_add(function.data.len())
            .ok_or_else(|| ProtectError::internal("ELF data layout overflow"))?;
        lifted.push(function);
    }
    let program = compile(&lifted, build_seed, arguments.options)
        .map_err(|error| ProtectError::context("compile protected program", error.into()))?;
    let vm_base = if let Some(base) = arguments.vm_base {
        base
    } else {
        elf.next_free_vaddr(0x1000)?
            .checked_add(0x1000)
            .ok_or_else(|| ProtectError::internal("VM base overflow"))?
    };
    if let Some(path) = &arguments.emit_source {
        let source = vmgen::source_for_audit(&program, vm_base)?;
        fs::write(path, source)
            .map_err(|error| ProtectError::io("write generated source", &error))?;
    }
    let blob = vmgen::build_vm(&program, vm_base, arguments.keep_temp)?;
    if blob.entry_vas.len() != targets.len() {
        return Err(ProtectError::internal("entry thunk count mismatch"));
    }
    let injection = inject(
        &input,
        &Injection::new(
            &blob.segment,
            blob.vm_vaddr,
            blob.payload_offset,
            blob.payload_len,
        ),
    )?;
    let mut image = injection.image;
    let mut patch_addresses = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter().enumerate() {
        let Some(entry) = blob.entry_vas.get(index).copied() else {
            return Err(ProtectError::internal("missing entry thunk"));
        };
        let patch = patch_relative_jump(&mut image, target.va, entry, true).map_err(|error| {
            ProtectError::context(format!("patch function {}", target.name), error.into())
        })?;
        patch_addresses.push((patch, target.va, target.size));
        if arguments.scrub {
            let scrub_start = patch
                .checked_add(5)
                .ok_or_else(|| ProtectError::internal("scrub start overflow"))?;
            let target_end = target
                .va
                .checked_add(target.size)
                .ok_or_else(|| ProtectError::internal("target end overflow"))?;
            if scrub_start < target_end {
                let length = usize::try_from(target_end - scrub_start)
                    .map_err(|_| ProtectError::internal("scrub length"))?;
                let domain = 0x5343_5255_4200_0001_u64
                    .wrapping_add(u64::try_from(index).unwrap_or(u64::MAX));
                let bytes = junk(&build_seed, domain, length);
                overwrite_vaddr(&mut image, scrub_start, &bytes)?;
            }
        }
    }
    let verified = Elf64::parse(&image)?;
    if verified.find_section(".sirus").is_none() {
        return Err(ProtectError::internal("injected segment disappeared"));
    }
    for (patch, _, _) in &patch_addresses {
        let bytes = verified
            .read_vaddr(*patch, 5)
            .ok_or_else(|| ProtectError::internal("patch bytes outside image"))?;
        if bytes.first() != Some(&0xe9) {
            return Err(ProtectError::internal("patch verification failed"));
        }
    }
    let permissions = fs::metadata(&arguments.input)
        .map(|metadata| metadata.permissions())
        .ok();
    let output_len = image.len();
    write_atomic(&arguments.output, &image, permissions)?;
    Ok(ProtectReport {
        functions: targets.len(),
        seed: build_seed,
        vm_vaddr: blob.vm_vaddr,
        payload_len: blob.payload_len,
        vm_len: blob.segment.len(),
        output_len,
        stats: program.stats(),
    })
}

fn resolve_pe_selector(pe: &Pe64<'_>, selector: &Selector) -> Result<Target> {
    match selector {
        Selector::Range { start, size } => Ok(Target {
            name: format!("range@{start:#x}"),
            va: *start,
            size: *size,
        }),
        Selector::Exact(name) => {
            let function = pe.find_function(name)?;
            Ok(Target {
                name: function.name,
                va: u64::from(function.rva),
                size: u64::from(function.size),
            })
        }
        Selector::Contains(needle) => {
            let matches = pe.find_functions_containing(needle)?;
            if matches.is_empty() {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::NotFound));
            }
            if matches.len() > 1 {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::Ambiguous));
            }
            let Some(function) = matches.first() else {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::NotFound));
            };
            Ok(Target {
                name: function.name.clone(),
                va: u64::from(function.rva),
                size: u64::from(function.size),
            })
        }
        Selector::Markers { begin, end } => {
            let begin_offset = pe.find_pattern_unique(begin)?;
            let end_offset = pe.find_pattern_unique(end)?;
            let begin_rva = pe
                .offset_to_rva(
                    u32::try_from(begin_offset)
                        .map_err(|_| ProtectError::internal("PE marker offset"))?,
                )
                .ok_or(ProtectError::Format(
                    sirus_binfmt::FormatError::RangeOutsideExecutable,
                ))?;
            let end_rva = pe
                .offset_to_rva(
                    u32::try_from(end_offset)
                        .map_err(|_| ProtectError::internal("PE marker offset"))?,
                )
                .ok_or(ProtectError::Format(
                    sirus_binfmt::FormatError::RangeOutsideExecutable,
                ))?;
            if end_rva <= begin_rva {
                return Err(ProtectError::usage(
                    "marker end must follow marker begin in the file",
                ));
            }
            Ok(Target {
                name: format!("markers@{begin_rva:#x}"),
                va: u64::from(begin_rva),
                size: u64::from(end_rva - begin_rva),
            })
        }
    }
}

fn scrub_pe_body(
    image: &mut [u8],
    pe: &Pe64<'_>,
    target: &Target,
    seed: &Seed,
    index: usize,
) -> Result<()> {
    let rva = u32::try_from(target.va).map_err(|_| ProtectError::internal("PE scrub RVA"))?;
    let size = u32::try_from(target.size).map_err(|_| ProtectError::internal("PE scrub size"))?;
    let offset = pe.rva_to_offset(rva, size).ok_or(ProtectError::Format(
        sirus_binfmt::FormatError::RangeOutsideExecutable,
    ))?;
    let start = usize::try_from(offset).map_err(|_| ProtectError::internal("PE scrub offset"))?;
    let length = usize::try_from(size).map_err(|_| ProtectError::internal("PE scrub length"))?;
    scrub_range(image, start, length, seed, index)
}

fn scrub_range(
    image: &mut [u8],
    start: usize,
    length: usize,
    seed: &Seed,
    index: usize,
) -> Result<()> {
    let domain = 0x5343_5255_4245_0002_u64.wrapping_add(u64::try_from(index).unwrap_or(u64::MAX));
    let bytes = junk(seed, domain, length);
    let end = start
        .checked_add(length)
        .ok_or_else(|| ProtectError::internal("PE scrub end"))?;
    let destination = image
        .get_mut(start..end)
        .ok_or_else(|| ProtectError::internal("PE scrub bounds"))?;
    destination.copy_from_slice(&bytes);
    Ok(())
}

fn attach_windows_exceptions(
    pe: &Pe64<'_>,
    windows: &mut vmgen::WindowsVmBlob,
) -> Result<(u32, Option<(u32, u32)>)> {
    let section_rva = pe
        .next_section_rva()
        .ok_or_else(|| ProtectError::internal("PE next section RVA"))?;
    let unwind = core::mem::take(&mut windows.unwind);
    let exception = append_exception_table(&mut windows.blob, pe, section_rva, &unwind)?;
    Ok((section_rva, exception))
}

#[allow(
    clippy::large_stack_frames,
    clippy::too_many_lines,
    reason = "PE protection owns the bounded lifted-program state and one linear injection transaction"
)]
fn protect_pe(arguments: &ProtectArgs, input: &[u8]) -> Result<ProtectReport> {
    let pe = Pe64::parse(input)?;
    if pe.find_section(".sirus").is_some() {
        return Err(ProtectError::Format(
            sirus_binfmt::FormatError::AlreadyProtected,
        ));
    }
    let mut targets = Vec::with_capacity(arguments.selectors.len());
    for selector in &arguments.selectors {
        let target = resolve_pe_selector(&pe, selector)?;
        let rva = u32::try_from(target.va).map_err(|_| ProtectError::internal("PE target RVA"))?;
        let size =
            u32::try_from(target.size).map_err(|_| ProtectError::internal("PE target size"))?;
        let section = pe.section_for_rva(rva, size).ok_or(ProtectError::Format(
            sirus_binfmt::FormatError::RangeOutsideExecutable,
        ))?;
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 || size == 0 {
            return Err(ProtectError::Format(
                sirus_binfmt::FormatError::RangeOutsideExecutable,
            ));
        }
        if pe.read_rva(rva, size).is_none() {
            return Err(ProtectError::Format(sirus_binfmt::FormatError::Bounds));
        }
        for other in &targets {
            let other_target: &Target = other;
            if ranges_overlap(target.va, target.size, other_target.va, other_target.size) {
                return Err(ProtectError::Format(sirus_binfmt::FormatError::Overlap));
            }
        }
        targets.push(target);
    }
    let mut functions = Vec::with_capacity(targets.len());
    let reader = PeReadOnly {
        pe: &pe,
        image_base: pe.optional_header().image_base,
    };
    let mut call_targets = Vec::with_capacity(targets.len());
    let image_base = pe.optional_header().image_base;
    for (index, target) in targets.iter().enumerate() {
        let call_va = image_base
            .checked_add(u64::from(
                u32::try_from(target.va)
                    .map_err(|_| ProtectError::internal("PE call target RVA"))?,
            ))
            .ok_or_else(|| ProtectError::internal("PE call target VA"))?;
        call_targets.push((
            call_va,
            u16::try_from(index).map_err(|_| ProtectError::internal("too many call targets"))?,
        ));
    }
    let mut data_base = 0_usize;
    for target in &targets {
        let rva = u32::try_from(target.va).map_err(|_| ProtectError::internal("PE target RVA"))?;
        let size =
            u32::try_from(target.size).map_err(|_| ProtectError::internal("PE target size"))?;
        let bytes = pe
            .read_rva(rva, size)
            .ok_or(ProtectError::Format(sirus_binfmt::FormatError::Bounds))?;
        let base = pe
            .optional_header()
            .image_base
            .checked_add(u64::from(rva))
            .ok_or_else(|| ProtectError::internal("PE lift base"))?;
        let function = lift_function_with_data_and_calls(
            bytes,
            base,
            &reader,
            &call_targets,
            data_base,
            StackAbi::WIN64,
        )?;
        data_base = data_base
            .checked_add(function.data.len())
            .ok_or_else(|| ProtectError::internal("PE data layout overflow"))?;
        functions.push(function);
    }
    let build_seed = match arguments.seed.as_deref() {
        Some(text) => parse_seed(text)?,
        None => seed(),
    };
    let program = compile(&functions, build_seed, arguments.options)?;
    let mut windows = vmgen::build_windows_vm(&program, arguments.keep_temp)?;
    let (section_rva, exception) = attach_windows_exceptions(&pe, &mut windows)?;
    let injection = append_pe_section(input, &windows.blob)?;
    if injection.section_rva != section_rva {
        return Err(ProtectError::internal("PE section RVA mismatch"));
    }
    let mut image = injection.image;
    if let Some((exception_rva, exception_size)) = exception {
        write_data_directory(
            &mut image,
            &pe,
            IMAGE_DIRECTORY_ENTRY_EXCEPTION,
            exception_rva,
            exception_size,
        )?;
        refresh_checksum(&mut image)?;
    }
    if windows.entry_offsets.len() != targets.len() {
        return Err(ProtectError::internal("Windows VM entry count"));
    }
    for (index, (target, offset)) in targets.iter().zip(&windows.entry_offsets).enumerate() {
        if arguments.scrub {
            scrub_pe_body(&mut image, &pe, target, &build_seed, index)?;
        }
        let entry_rva = injection
            .section_rva
            .checked_add(
                u32::try_from(*offset).map_err(|_| ProtectError::internal("PE VM entry offset"))?,
            )
            .ok_or_else(|| ProtectError::internal("PE VM entry RVA"))?;
        let from = u32::try_from(target.va).map_err(|_| ProtectError::internal("PE patch RVA"))?;
        let _ = patch_relative_jump_rva(&mut image, from, entry_rva, false)?;
    }
    let metadata = fs::metadata(&arguments.input)
        .map_err(|error| ProtectError::io("read input permissions", &error))?;
    write_atomic(&arguments.output, &image, Some(metadata.permissions()))?;
    Ok(ProtectReport {
        functions: targets.len(),
        seed: build_seed,
        vm_vaddr: u64::from(injection.section_rva),
        payload_len: program.payload().len(),
        vm_len: windows.blob.len(),
        output_len: image.len(),
        stats: program.stats(),
    })
}

/// Prints a report.
///
/// # Errors
///
/// Propagates output I/O errors.
#[inline]
pub fn print_report(report: &ProtectReport, output: &mut impl Write) -> Result<()> {
    writeln!(
        output,
        "protected {} function(s); seed {}; VM {:#x}; VM segment {} bytes; payload {} bytes; output {} bytes",
        report.functions,
        format_seed(&report.seed),
        report.vm_vaddr,
        report.vm_len,
        report.payload_len,
        report.output_len
    )
    .map_err(|error| ProtectError::io("write report", &error))?;
    writeln!(
        output,
        "manifest {} entries, original blocks {}, decoy blocks {}, body {} bytes",
        report.stats.manifest_entries,
        report.stats.original_blocks,
        report.stats.decoy_blocks,
        report.stats.body_bytes
    )
    .map_err(|error| ProtectError::io("write report", &error))
}

/// Runs the local hardened-runtime checks.
///
/// # Errors
///
/// Propagates output errors.
#[inline]
pub fn harden_check(output: &mut impl Write) -> Result<()> {
    let debugger = sirus_hardened::debugger_present();
    let start = sirus_hardened::rdtsc();
    sirus_hardened::lfence();
    let end = sirus_hardened::rdtsc();
    writeln!(
        output,
        "debugger_present={debugger}\nhypervisor_present={}\ntsc_delta={}\ntiming_ok={}",
        sirus_hardened::hypervisor_present(),
        end.wrapping_sub(start),
        sirus_hardened::timing_ok(start, u64::MAX)
    )
    .map_err(|error| ProtectError::io("write hardened check", &error))?;
    match sirus_hardened::host::debug_registers() {
        Some(registers) => {
            writeln!(
                output,
                "debug_registers=0x{:016x},0x{:016x},0x{:016x},0x{:016x}",
                registers[0], registers[1], registers[2], registers[3]
            )
            .map_err(|error| ProtectError::io("write debug registers", &error))?;
        }
        None => {
            writeln!(output, "debug_registers=unsupported")
                .map_err(|error| ProtectError::io("write debug registers", &error))?;
        }
    }
    Ok(())
}

/// Prints binary structure for inspection.
///
/// # Errors
///
/// Propagates parse and output errors.
pub fn inspect(path: &Path, output: &mut impl Write) -> Result<()> {
    let bytes = fs::read(path).map_err(|error| ProtectError::io("read inspected file", &error))?;
    if bytes.starts_with(b"MZ") {
        return inspect_pe(&bytes, output);
    }
    let elf = Elf64::parse(&bytes)?;
    writeln!(
        output,
        "ELF64 type={} machine={} entry={:#x} phdrs={} shdrs={}",
        elf.header().kind,
        elf.header().machine,
        elf.header().entry,
        elf.program_headers().len(),
        elf.section_headers().len()
    )
    .map_err(|error| ProtectError::io("write inspection", &error))?;
    writeln!(
        output,
        "max-load-end={:#x} next-free={:#x} protected={}",
        elf.max_load_end(),
        elf.next_free_vaddr(0x1000)?,
        elf.find_section(".sirus").is_some()
    )
    .map_err(|error| ProtectError::io("write inspection", &error))?;
    for (index, program) in elf.program_headers().iter().enumerate() {
        if program.p_type != PT_LOAD {
            continue;
        }
        writeln!(
            output,
            "LOAD[{index}] off={:#x} vaddr={:#x} filesz={:#x} memsz={:#x} flags={}",
            program.p_offset, program.p_vaddr, program.p_filesz, program.p_memsz, program.p_flags
        )
        .map_err(|error| ProtectError::io("write inspection", &error))?;
    }
    let functions = elf.functions()?;
    writeln!(output, "functions={}", functions.len())
        .map_err(|error| ProtectError::io("write inspection", &error))?;
    for function in functions.iter().take(40) {
        writeln!(
            output,
            "  FUNC {:#x} size={} {}",
            function.value, function.size, function.name
        )
        .map_err(|error| ProtectError::io("write inspection", &error))?;
    }
    Ok(())
}

fn inspect_pe(bytes: &[u8], output: &mut impl Write) -> Result<()> {
    let pe = Pe64::parse(bytes)?;
    writeln!(
        output,
        "PE32+ machine={} entry-rva={:#x} image-base={:#x} sections={}",
        pe.coff_header().machine,
        pe.optional_header().entry_rva,
        pe.optional_header().image_base,
        pe.sections().len()
    )
    .map_err(|error| ProtectError::io("write PE inspection", &error))?;
    writeln!(
        output,
        "size-of-image={:#x} headers={:#x} checksum={:#x} protected={}",
        pe.optional_header().size_of_image,
        pe.optional_header().size_of_headers,
        pe.optional_header().checksum,
        pe.find_section(".sirus").is_some()
    )
    .map_err(|error| ProtectError::io("write PE inspection", &error))?;
    for (index, section) in pe.sections().iter().enumerate() {
        writeln!(
            output,
            "SECTION[{index}] {:<8} rva={:#x} vsize={:#x} raw={:#x} flags={:#x}",
            section.name_str().unwrap_or("<invalid>"),
            section.virtual_address,
            section.virtual_size,
            section.raw_size,
            section.characteristics
        )
        .map_err(|error| ProtectError::io("write PE inspection", &error))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProtectArgs, Selector, inspect, protect, scrub_range};
    use sirus_core::program::CompileOptions;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sandbox() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("sirus-pipeline-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("sandbox");
        path
    }

    fn compile_fixture(directory: &Path) -> PathBuf {
        let output = directory.join("victim");
        let result = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()))
            .arg("--edition=2021")
            .arg("-C")
            .arg("opt-level=2")
            .arg("-C")
            .arg("panic=abort")
            .arg("-C")
            .arg("debuginfo=0")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/victim.rs"
            ))
            .arg("-o")
            .arg(&output)
            .output()
            .expect("rustc fixture");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        output
    }

    fn arguments(input: &Path, output: &Path, selectors: Vec<Selector>) -> ProtectArgs {
        ProtectArgs {
            input: input.to_path_buf(),
            output: output.to_path_buf(),
            selectors,
            seed: Some(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
            ),
            options: CompileOptions::new(),
            keep_temp: false,
            scrub: true,
            vm_base: None,
            emit_source: None,
        }
    }

    fn synthetic_pe() -> Vec<u8> {
        let mut data = vec![0_u8; 0x600];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84_usize;
        data[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());
        let optional = coff + 20;
        data[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        data[optional + 16..optional + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
        data[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        data[optional + 56..optional + 60].copy_from_slice(&0x3000_u32.to_le_bytes());
        data[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        data[optional + 108..optional + 112].copy_from_slice(&16_u32.to_le_bytes());
        let table = optional + 240;
        data[table..table + 8].copy_from_slice(b".text\0\0\0");
        data[table + 8..table + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        data[table + 12..table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[table + 16..table + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        data[table + 20..table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        data[table + 36..table + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        data[0x200..0x204].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
        data[0x204..0x20f].fill(0x90);
        data[0x20f] = 0xc3;
        data[0x210..0x214].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
        data[0x214..0x21f].fill(0x90);
        data[0x21f] = 0xc3;
        data[coff + 8..coff + 12].copy_from_slice(&0x500_u32.to_le_bytes());
        data[coff + 12..coff + 16].copy_from_slice(&2_u32.to_le_bytes());
        data[0x500..0x524].fill(0);
        data[0x500..0x504].copy_from_slice(&0_u32.to_le_bytes());
        data[0x504..0x508].copy_from_slice(&4_u32.to_le_bytes());
        data[0x508..0x50c].copy_from_slice(&0_u32.to_le_bytes());
        data[0x50c..0x50e].copy_from_slice(&1_u16.to_le_bytes());
        data[0x50e..0x510].copy_from_slice(&0x20_u16.to_le_bytes());
        data[0x510] = 2;
        data[0x500 + 18..0x500 + 22].copy_from_slice(&0_u32.to_le_bytes());
        data[0x500 + 22..0x500 + 26].copy_from_slice(&15_u32.to_le_bytes());
        data[0x500 + 26..0x500 + 30].copy_from_slice(&0x10_u32.to_le_bytes());
        data[0x500 + 30..0x500 + 32].copy_from_slice(&1_u16.to_le_bytes());
        data[0x500 + 32..0x500 + 34].copy_from_slice(&0x20_u16.to_le_bytes());
        data[0x500 + 34] = 2;
        data[0x524..0x528].copy_from_slice(&24_u32.to_le_bytes());
        data[0x528..0x532].copy_from_slice(b"sirus_demo");
        data[0x532] = 0;
        data[0x533..0x538].copy_from_slice(b"other");
        data[0x538] = 0;
        data
    }

    fn windows_toolchain_available() -> bool {
        let rustc = Command::new("rustc")
            .args([
                "--print",
                "target-libdir",
                "--target",
                "x86_64-pc-windows-gnu",
            ])
            .output();
        let rustc_ok = rustc
            .ok()
            .filter(|output| output.status.success())
            .is_some_and(|output| {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                Path::new(&path).is_dir()
            });
        rustc_ok
            && Command::new("x86_64-w64-mingw32-gcc")
                .arg("--version")
                .output()
                .is_ok()
            && Command::new("lld-link").arg("--version").output().is_ok()
    }

    #[test]
    fn pe_pipeline_smoke_when_toolchain_available() {
        if !windows_toolchain_available() {
            return;
        }
        let directory = sandbox();
        let input = directory.join("input.exe");
        let output = directory.join("protected.exe");
        fs::write(&input, synthetic_pe()).expect("write pe");
        let report = protect(&arguments(
            &input,
            &output,
            vec![Selector::Range {
                start: 0x1000,
                size: 4,
            }],
        ))
        .expect("protect pe");
        assert_eq!(report.functions, 1);
        let mut inspection = Vec::new();
        inspect(&output, &mut inspection).expect("inspect pe");
        assert!(String::from_utf8_lossy(&inspection).contains("protected=true"));
    }

    #[test]
    fn pipeline_markers_emit_source_and_error_paths() {
        let directory = sandbox();
        let victim = compile_fixture(&directory);
        let bytes = fs::read(&victim).expect("read victim");
        let elf = sirus_binfmt::elf::Elf64::parse(&bytes).expect("parse victim");
        let function = elf
            .find_functions_containing("sirus_demo_check")
            .expect("find check")
            .first()
            .expect("check")
            .to_owned();
        let source = directory.join("vm.rs");
        let mut emit = arguments(
            &victim,
            &directory.join("emit"),
            vec![Selector::Exact(function.name.to_owned())],
        );
        emit.emit_source = Some(source.clone());
        protect(&emit).expect("emit source");
        assert!(source.is_file());

        let bad = directory.join("bad");
        fs::write(&bad, b"not an executable").expect("bad input");
        assert!(
            protect(&arguments(
                &bad,
                &directory.join("bad-out"),
                vec![Selector::Exact("x".to_owned())],
            ))
            .is_err()
        );
        let directory_output = directory.join("directory-output");
        fs::create_dir(&directory_output).expect("directory output");
        assert!(
            protect(&arguments(
                &victim,
                &directory_output,
                vec![Selector::Exact("x".to_owned())],
            ))
            .is_err()
        );
    }

    #[test]
    fn pe_symbol_selectors_are_resolved() {
        if !windows_toolchain_available() {
            return;
        }
        let directory = sandbox();
        let input = directory.join("symbols.exe");
        fs::write(&input, synthetic_pe()).expect("write pe");
        protect(&arguments(
            &input,
            &directory.join("exact.exe"),
            vec![Selector::Exact("sirus_demo".to_owned())],
        ))
        .expect("exact pe");
        protect(&arguments(
            &input,
            &directory.join("contains.exe"),
            vec![Selector::Contains("sirus".to_owned())],
        ))
        .expect("contains pe");
        assert!(
            protect(&arguments(
                &input,
                &directory.join("missing.exe"),
                vec![Selector::Exact("missing".to_owned())],
            ))
            .is_err()
        );
        assert!(
            protect(&arguments(
                &input,
                &directory.join("ambiguous.exe"),
                vec![Selector::Contains("e".to_owned())],
            ))
            .is_err()
        );
    }

    #[test]
    fn pipeline_selectors_and_inspection_are_exercised_in_process() {
        let directory = sandbox();
        let victim = compile_fixture(&directory);
        let victim_bytes = fs::read(&victim).expect("read victim");
        let victim_elf = sirus_binfmt::elf::Elf64::parse(&victim_bytes).expect("parse victim");
        let exact_name = victim_elf
            .find_functions_containing("sirus_demo_check")
            .expect("find check")
            .first()
            .expect("check symbol")
            .name
            .to_owned();
        let exact_output = directory.join("exact");
        let report = protect(&arguments(
            &victim,
            &exact_output,
            vec![Selector::Exact(exact_name.clone())],
        ))
        .expect("exact protect");
        assert_eq!(report.functions, 1);
        let mut inspection = Vec::new();
        inspect(&exact_output, &mut inspection).expect("inspect");
        assert!(String::from_utf8_lossy(&inspection).contains("protected=true"));
        assert!(
            protect(&arguments(
                &exact_output,
                &directory.join("again"),
                vec![Selector::Exact(exact_name.clone())],
            ))
            .is_err()
        );

        let contains_output = directory.join("contains");
        protect(&arguments(
            &victim,
            &contains_output,
            vec![Selector::Contains("sirus_demo_check".to_owned())],
        ))
        .expect("contains protect");

        let function = victim_elf
            .find_functions_containing("sirus_demo_loop")
            .expect("find loop")
            .first()
            .expect("loop symbol")
            .to_owned();
        let range_output = directory.join("range");
        protect(&arguments(
            &victim,
            &range_output,
            vec![Selector::Range {
                start: function.value,
                size: function.size,
            }],
        ))
        .expect("range protect");

        assert!(
            protect(&arguments(
                &victim,
                &directory.join("missing"),
                vec![Selector::Exact("missing".to_owned())],
            ))
            .is_err()
        );
        assert!(
            protect(&arguments(
                &victim,
                &directory.join("ambiguous"),
                vec![Selector::Contains("sirus_demo".to_owned())],
            ))
            .is_err()
        );
        assert!(
            protect(&arguments(
                &victim,
                &directory.join("overlap"),
                vec![
                    Selector::Exact(exact_name.clone()),
                    Selector::Exact(exact_name),
                ],
            ))
            .is_err()
        );
        assert!(
            protect(&arguments(
                &victim,
                &directory.join("markers"),
                vec![Selector::Markers {
                    begin: b"sirus-marker-missing".to_vec(),
                    end: b"sirus-marker-end".to_vec(),
                }],
            ))
            .is_err()
        );
    }

    #[test]
    fn scrub_range_overwrites_and_validates_bounds() {
        let seed = [0x42_u8; 32];
        let mut image = [0x90_u8; 16];
        scrub_range(&mut image, 4, 8, &seed, 0).expect("scrub");
        assert_eq!(image.first_chunk::<4>(), Some(&[0x90_u8; 4]));
        assert_ne!(image.get(4..12), Some(&[0x90_u8; 8][..]));
        let mut second = [0x90_u8; 16];
        scrub_range(&mut second, 4, 8, &seed, 0).expect("deterministic");
        assert_eq!(image, second);
        assert!(scrub_range(&mut image, 15, 2, &seed, 0).is_err());
        assert!(scrub_range(&mut image, usize::MAX, 1, &seed, 0).is_err());
    }
}
