//! Command-line parsing for the Sirus protector.

use std::ffi::OsString;
use std::path::PathBuf;

use sirus_core::program::CompileOptions;

use crate::entropy::parse_hex_bytes;
use crate::error::{ProtectError, Result};

/// One target-selection strategy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// Exact symbol name.
    Exact(String),
    /// Unique substring of one symbol name.
    Contains(String),
    /// Byte markers delimiting a native range.
    Markers { begin: Vec<u8>, end: Vec<u8> },
}

/// Parsed protect command.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ProtectArgs {
    /// Input executable.
    pub input: PathBuf,
    /// Output executable.
    pub output: PathBuf,
    /// Target selectors.
    pub selectors: Vec<Selector>,
    /// Optional deterministic seed.
    pub seed: Option<String>,
    /// Compiler options.
    pub options: CompileOptions,
    /// Keep generated VM source and blob for audit.
    pub keep_temp: bool,
    /// Destroy original protected function bodies after patching.
    pub scrub: bool,
    /// Optional VM base override.
    pub vm_base: Option<u64>,
    /// Optional path for generated-source audit output.
    pub emit_source: Option<PathBuf>,
}

/// Top-level action.
#[derive(Clone, Debug)]
pub enum Action {
    /// Protect an executable.
    Protect(ProtectArgs),
    /// Inspect an executable.
    Inspect(PathBuf),
    /// Print version.
    Version,
    /// Print help.
    Help,
}

/// Parses process arguments.
pub fn parse() -> Result<Action> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(first) = arguments.first() else {
        return Ok(Action::Help);
    };
    let Some(command) = first.to_str() else {
        return Err(ProtectError::usage("command must be valid UTF-8"));
    };
    match command {
        "protect" => parse_protect(&arguments),
        "inspect" => parse_inspect(&arguments),
        "version" | "--version" | "-V" => Ok(Action::Version),
        "help" | "--help" | "-h" => Ok(Action::Help),
        other => Err(ProtectError::usage(format!(
            "unknown command `{other}`; expected protect, inspect, version, or help"
        ))),
    }
}

fn next_value(arguments: &[OsString], index: &mut usize, flag: &str) -> Result<OsString> {
    *index = index.saturating_add(1);
    arguments
        .get(*index)
        .cloned()
        .ok_or_else(|| ProtectError::usage(format!("{flag} requires a value")))
}

fn text_value(arguments: &[OsString], index: &mut usize, flag: &str) -> Result<String> {
    let value = next_value(arguments, index, flag)?;
    value
        .into_string()
        .map_err(|_| ProtectError::usage(format!("{flag} value must be valid UTF-8")))
}

fn number_value<T>(arguments: &[OsString], index: &mut usize, flag: &str) -> Result<T>
where
    T: core::str::FromStr,
{
    let text = text_value(arguments, index, flag)?;
    text.parse::<T>()
        .map_err(|_| ProtectError::usage(format!("{flag} has an invalid numeric value")))
}

fn hex_value(arguments: &[OsString], index: &mut usize, flag: &str) -> Result<u64> {
    let text = text_value(arguments, index, flag)?;
    let trimmed = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(&text);
    u64::from_str_radix(trimmed, 16)
        .map_err(|_| ProtectError::usage(format!("{flag} must be hexadecimal")))
}

fn parse_protect(arguments: &[OsString]) -> Result<Action> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut selectors = Vec::new();
    let mut pending_marker: Option<Vec<u8>> = None;
    let mut seed: Option<String> = None;
    let mut options = CompileOptions::new();
    let mut keep_temp = false;
    let mut scrub = true;
    let mut vm_base: Option<u64> = None;
    let mut emit_source: Option<PathBuf> = None;
    let mut index = 1_usize;
    while index < arguments.len() {
        let Some(flag) = arguments.get(index).and_then(|value| value.to_str()) else {
            return Err(ProtectError::usage("flags must be valid UTF-8"));
        };
        match flag {
            "--input" => input = Some(PathBuf::from(next_value(arguments, &mut index, flag)?)),
            "--output" => output = Some(PathBuf::from(next_value(arguments, &mut index, flag)?)),
            "--function" => {
                selectors.push(Selector::Exact(text_value(arguments, &mut index, flag)?));
            }
            "--function-contains" => {
                selectors.push(Selector::Contains(text_value(arguments, &mut index, flag)?));
            }
            "--marker-begin" => {
                if pending_marker.is_some() {
                    return Err(ProtectError::usage(
                        "--marker-begin was given twice without --marker-end",
                    ));
                }
                let begin_text = text_value(arguments, &mut index, flag)?;
                pending_marker = Some(parse_hex_bytes(&begin_text)?);
            }
            "--marker-end" => {
                let Some(begin) = pending_marker.take() else {
                    return Err(ProtectError::usage(
                        "--marker-end requires a preceding --marker-begin",
                    ));
                };
                let end_text = text_value(arguments, &mut index, flag)?;
                selectors.push(Selector::Markers {
                    begin,
                    end: parse_hex_bytes(&end_text)?,
                });
            }
            "--seed" => seed = Some(text_value(arguments, &mut index, flag)?),
            "--fuel" => options.fuel = number_value(arguments, &mut index, flag)?,
            "--mba-depth" => options.mba_depth = number_value(arguments, &mut index, flag)?,
            "--mba-budget" => options.mba_budget = number_value(arguments, &mut index, flag)?,
            "--decoys" => options.decoys = number_value(arguments, &mut index, flag)?,
            "--vm-base" => vm_base = Some(hex_value(arguments, &mut index, flag)?),
            "--emit-source" => {
                emit_source = Some(PathBuf::from(next_value(arguments, &mut index, flag)?));
            }
            "--keep-temp" => keep_temp = true,
            "--no-scrub" => scrub = false,
            "--help" | "-h" => return Ok(Action::Help),
            _ => {
                return Err(ProtectError::usage(format!(
                    "unknown protect flag `{flag}`"
                )));
            }
        }
        index = index.saturating_add(1);
    }
    let Some(input) = input else {
        return Err(ProtectError::usage("protect requires --input"));
    };
    let Some(output) = output else {
        return Err(ProtectError::usage("protect requires --output"));
    };
    if pending_marker.is_some() {
        return Err(ProtectError::usage(
            "--marker-begin requires a matching --marker-end",
        ));
    }
    if selectors.is_empty() {
        return Err(ProtectError::usage(
            "protect requires at least one target selector",
        ));
    }
    Ok(Action::Protect(ProtectArgs {
        input,
        output,
        selectors,
        seed,
        options,
        keep_temp,
        scrub,
        vm_base,
        emit_source,
    }))
}

fn parse_inspect(arguments: &[OsString]) -> Result<Action> {
    let mut path: Option<PathBuf> = None;
    let mut index = 1_usize;
    while index < arguments.len() {
        let Some(value) = arguments.get(index) else {
            break;
        };
        let Some(flag) = value.to_str() else {
            return Err(ProtectError::usage("inspect path must be valid UTF-8"));
        };
        if flag == "--help" || flag == "-h" {
            return Ok(Action::Help);
        }
        if path.is_some() {
            return Err(ProtectError::usage("inspect accepts one path"));
        }
        path = Some(PathBuf::from(value.clone()));
        index = index.saturating_add(1);
    }
    path.map(Action::Inspect)
        .ok_or_else(|| ProtectError::usage("inspect requires a path"))
}

/// Help text.
#[inline]
#[must_use]
pub const fn help_text() -> &'static str {
    "sirus - zero-dependency polymorphic code virtualizer\n\n\
     Usage:\n\
     \x20 sirus protect --input <ELF> --output <ELF> <selector> [options]\n\
     \x20 sirus inspect <ELF>\n\
     \x20 sirus version\n\n\
     Selectors:\n\
     \x20 --function <exact-symbol>\n\
     \x20 --function-contains <unique-substring>\n\
     \x20 --marker-begin <hex> --marker-end <hex>\n\n\
     Options:\n\
     \x20 --seed <64-hex>          deterministic build seed\n\
     \x20 --fuel <n>               runtime instruction budget (default 2000000)\n\
     \x20 --mba-depth <n>          MBA rewrite depth (0..=8, default 3)\n\
     \x20 --mba-budget <n>         MBA node budget (default 512)\n\
     \x20 --decoys <n>             opaque decoy pairs per function (0..=8, default 2)\n\
     \x20 --vm-base <hex>          override VM virtual address\n\
     \x20 --emit-source <path>     write generated VM source for audit\n\
     \x20 --keep-temp              keep compiler temporary files\n\
     \x20 --no-scrub               do not destroy original function bodies\n"
}
