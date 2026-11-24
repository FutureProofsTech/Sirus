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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
///
/// # Errors
///
/// Returns a usage error for unknown commands, flags, missing values, invalid
/// numbers, or invalid marker pairs.
#[inline]
pub fn parse() -> Result<Action> {
    parse_from(std::env::args_os().skip(1))
}

fn parse_from<I: IntoIterator<Item = OsString>>(values: I) -> Result<Action> {
    let arguments: Vec<OsString> = values.into_iter().collect();
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

fn apply_profile(options: &mut CompileOptions, profile: &str) -> Result<()> {
    match profile {
        "max" => {
            options.mba_depth = 3;
            options.mba_budget = 512;
            options.decoys = 2;
        }
        "balanced" => {
            options.mba_depth = 1;
            options.mba_budget = 128;
            options.decoys = 1;
        }
        "minimal" => {
            options.mba_depth = 0;
            options.mba_budget = 0;
            options.decoys = 0;
        }
        other => {
            return Err(ProtectError::usage(format!(
                "unknown profile `{other}`; expected max, balanced, or minimal"
            )));
        }
    }
    Ok(())
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
            "--profile" => {
                let profile = text_value(arguments, &mut index, flag)?;
                apply_profile(&mut options, &profile)?;
            }
            "--fuel" => options.fuel = number_value(arguments, &mut index, flag)?,
            "--mba-depth" => options.mba_depth = number_value(arguments, &mut index, flag)?,
            "--mba-budget" => options.mba_budget = number_value(arguments, &mut index, flag)?,
            "--decoys" => options.decoys = number_value(arguments, &mut index, flag)?,
            "--constant-time" => options.constant_time = true,
            "--constant-time-passes" => {
                options.constant_time_passes = number_value(arguments, &mut index, flag)?;
            }
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
     \x20 --profile <name>         max (default), balanced, or minimal\n\
     \x20 --fuel <n>               runtime instruction budget (default 2000000)\n\
     \x20 --mba-depth <n>          MBA rewrite depth (0..=8, default 3)\n\
     \x20 --mba-budget <n>         MBA node budget (default 512)\n\
     \x20 --decoys <n>             opaque decoy pairs per function (0..=8, default 2)\n\
     \x20 --constant-time         oblivious branch/loop execution; reject private memory\n\
     \x20 --constant-time-passes <n> fixed oblivious passes (1..=4096, default 256)\n\
     \x20 --vm-base <hex>          override VM virtual address\n\
     \x20 --emit-source <path>     write generated VM source for audit\n\
     \x20 --keep-temp              keep compiler temporary files\n\
     \x20 --no-scrub               do not destroy original function bodies\n"
}

#[cfg(test)]
mod tests {
    use super::{Action, Selector, parse_from};
    use crate::error::ProtectError;
    use sirus_core::program::CompileOptions;
    use std::ffi::OsString;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn usage_error(result: &super::Result<Action>) -> bool {
        matches!(result, Err(ProtectError::Usage(_)))
    }

    const SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn parses_help_and_version() {
        assert_eq!(parse_from(arguments(&[])), Ok(Action::Help));
        assert_eq!(parse_from(arguments(&["help"])), Ok(Action::Help));
        assert_eq!(parse_from(arguments(&["version"])), Ok(Action::Version));
        assert!(super::help_text().contains("sirus protect"));
    }

    #[test]
    fn parses_full_protect_command() {
        let result = parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function-contains",
            "demo",
            "--seed",
            SEED,
            "--fuel",
            "100",
            "--mba-depth",
            "1",
            "--mba-budget",
            "32",
            "--decoys",
            "0",
            "--vm-base",
            "0x10000",
            "--emit-source",
            "vm.rs",
            "--keep-temp",
            "--no-scrub",
        ]));
        let action = result.expect("protect parse");
        let Action::Protect(parsed) = action else {
            panic!("expected protect");
        };
        assert_eq!(parsed.input, std::path::PathBuf::from("in"));
        assert_eq!(parsed.output, std::path::PathBuf::from("out"));
        assert_eq!(
            parsed.selectors,
            vec![Selector::Contains("demo".to_owned())]
        );
        assert_eq!(parsed.seed.as_deref(), Some(SEED));
        assert_eq!(parsed.options.fuel, 100);
        assert_eq!(parsed.options.mba_depth, 1);
        assert_eq!(parsed.options.mba_budget, 32);
        assert_eq!(parsed.options.decoys, 0);
        assert_eq!(parsed.vm_base, Some(0x10000));
        assert_eq!(parsed.emit_source, Some(std::path::PathBuf::from("vm.rs")));
        assert!(parsed.keep_temp);
        assert!(!parsed.scrub);
    }

    #[test]
    fn profiles_set_bounded_compiler_options_and_flags_override() {
        let action = parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "demo",
            "--profile",
            "balanced",
        ]))
        .expect("balanced profile");
        let Action::Protect(parsed) = action else {
            panic!("expected protect");
        };
        assert_eq!(parsed.options.mba_depth, 1);
        assert_eq!(parsed.options.mba_budget, 128);
        assert_eq!(parsed.options.decoys, 1);

        let action = parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "demo",
            "--profile",
            "minimal",
            "--mba-depth",
            "2",
        ]))
        .expect("profile override");
        let Action::Protect(parsed) = action else {
            panic!("expected protect");
        };
        assert_eq!(parsed.options.mba_depth, 2);
        assert_eq!(parsed.options.mba_budget, 0);

        assert!(usage_error(&parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "demo",
            "--profile",
            "unknown",
        ]))));
    }

    #[test]
    fn parses_markers_and_exact_symbols() {
        let result = parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "exact",
            "--marker-begin",
            "48 8b",
            "--marker-end",
            "c3",
        ]));
        let action = result.expect("parse markers");
        let Action::Protect(parsed) = action else {
            panic!("expected protect");
        };
        assert_eq!(parsed.selectors.len(), 2);
        assert_eq!(
            parsed.selectors.first(),
            Some(&Selector::Exact("exact".to_owned()))
        );
        assert!(
            matches!(parsed.selectors.get(1), Some(Selector::Markers { begin, end }) if begin == &[0x48, 0x8b] && end == &[0xc3])
        );
    }

    #[test]
    fn parses_inspect() {
        assert_eq!(
            parse_from(arguments(&["inspect", "binary"])),
            Ok(Action::Inspect(std::path::PathBuf::from("binary")))
        );
        assert_eq!(
            parse_from(arguments(&["inspect", "--help"])),
            Ok(Action::Help)
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_incomplete_forms() {
        use std::os::unix::ffi::OsStringExt;

        assert!(usage_error(&parse_from(vec![OsString::from_vec(vec![
            0xff
        ])])));
        assert!(usage_error(&parse_from(vec![
            OsString::from("protect"),
            OsString::from_vec(vec![0xff]),
        ])));
        assert!(usage_error(&parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--function",
            "demo",
        ]))));
        assert!(usage_error(&parse_from(arguments(&[
            "protect", "--input", "in", "--output", "out",
        ]))));
        assert!(usage_error(&parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--marker-begin",
            "48",
            "--marker-begin",
            "90",
        ]))));
        assert!(usage_error(&parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--marker-end",
            "c3",
        ]))));
        assert!(usage_error(&parse_from(vec![
            OsString::from("inspect"),
            OsString::from_vec(vec![0xff]),
        ])));
        assert!(usage_error(&parse_from(arguments(&["inspect", "a", "b"]))));
        let action = parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "demo",
            "--profile",
            "max",
        ]))
        .expect("max profile");
        let Action::Protect(parsed) = action else {
            panic!("expected protect");
        };
        assert_eq!(parsed.options.mba_depth, 3);
        assert_eq!(parsed.options.mba_budget, 512);
        assert_eq!(parsed.options.decoys, 2);
    }

    #[test]
    fn parses_constant_time_flag() {
        let action = parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "demo",
            "--constant-time",
        ]))
        .expect("constant time");
        let Action::Protect(parsed) = action else {
            panic!("expected protect");
        };
        assert!(parsed.options.constant_time);
    }

    #[test]
    fn parses_constant_time_passes() {
        let action = parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "demo",
            "--constant-time",
            "--constant-time-passes",
            "64",
        ]))
        .expect("constant time passes");
        let Action::Protect(parsed) = action else {
            panic!("expected protect");
        };
        assert!(parsed.options.constant_time);
        assert_eq!(parsed.options.constant_time_passes, 64);
    }

    #[test]
    fn rejects_bad_commands_and_flags() {
        assert!(usage_error(&parse_from(arguments(&["unknown"]))));
        assert!(usage_error(&parse_from(arguments(&["protect"]))));
        assert!(usage_error(&parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "f",
            "--unknown"
        ]))));
        assert!(usage_error(&parse_from(arguments(&["protect", "--input"]))));
        assert!(usage_error(&parse_from(arguments(&["inspect"]))));
        assert!(usage_error(&parse_from(arguments(&["inspect", "a", "b"]))));
    }

    #[test]
    fn rejects_invalid_numbers_and_markers() {
        let base = [
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "f",
        ];
        let mut bad_fuel = base.to_vec();
        bad_fuel.extend(["--fuel", "not-a-number"]);
        assert!(usage_error(&parse_from(arguments(&bad_fuel))));
        let mut bad_depth = base.to_vec();
        bad_depth.extend(["--mba-depth", "999"]);
        assert!(usage_error(&parse_from(arguments(&bad_depth))));
        let mut bad_budget = base.to_vec();
        bad_budget.extend(["--mba-budget", "x"]);
        assert!(usage_error(&parse_from(arguments(&bad_budget))));
        let mut bad_vm_base = base.to_vec();
        bad_vm_base.extend(["--vm-base", "not-hex"]);
        assert!(usage_error(&parse_from(arguments(&bad_vm_base))));
        let mut bad_hex = base.to_vec();
        bad_hex.extend(["--marker-begin", "zz"]);
        assert!(usage_error(&parse_from(arguments(&bad_hex))));
        let mut missing_end = base.to_vec();
        missing_end.extend(["--marker-begin", "aa"]);
        assert!(usage_error(&parse_from(arguments(&missing_end))));
        let mut missing_begin = base.to_vec();
        missing_begin.extend(["--marker-end", "aa"]);
        assert!(usage_error(&parse_from(arguments(&missing_begin))));
    }

    #[test]
    fn default_options_are_production_defaults() {
        let result = parse_from(arguments(&[
            "protect",
            "--input",
            "in",
            "--output",
            "out",
            "--function",
            "f",
        ]));
        let Action::Protect(parsed) = result.expect("protect") else {
            panic!("expected protect");
        };
        let defaults = CompileOptions::new();
        assert_eq!(parsed.options, defaults);
        assert!(parsed.scrub);
        assert!(!parsed.keep_temp);
    }
}
