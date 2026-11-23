//! Marker-based target discovery end-to-end test.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration test uses assertion panics and fixed fixture offsets"
)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use sirus_binfmt::elf::Elf64;

const VICTIM: &str = r#"
#[inline(never)]
fn sirus_marker_target(a: u64, b: u64) -> u64 {
    if a > b {
        a.wrapping_mul(5).wrapping_add(b) ^ 0xfeed_face_dead_beef
    } else {
        b.wrapping_sub(a).wrapping_mul(3)
    }
}
fn main() {
    let mut arguments = std::env::args().skip(1);
    let first = arguments.next().and_then(|v| v.parse().ok()).unwrap_or(9);
    let second = arguments.next().and_then(|v| v.parse().ok()).unwrap_or(2);
    println!("{}", sirus_marker_target(first, second));
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-markers-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("sandbox");
    path
}

fn compile_victim(path: &Path) -> PathBuf {
    let source = path.join("victim.rs");
    let binary = path.join("victim");
    fs::write(&source, VICTIM).expect("victim source");
    let output = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()))
        .arg("--edition=2021")
        .arg("-C")
        .arg("opt-level=2")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("debuginfo=0")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("compile victim");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn run(binary: &Path, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .output()
        .expect("run binary")
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn unique_marker(image: &[u8], elf: &Elf64<'_>, start: usize) -> Vec<u8> {
    for length in [16_usize, 24, 32, 48] {
        if let Some(candidate) = image.get(start..start.saturating_add(length)) {
            if elf.find_pattern_unique(candidate) == Ok(start) {
                return candidate.to_vec();
            }
        }
    }
    panic!("could not find a unique marker at {start:#x}");
}

#[test]
fn marker_discovery_protects_the_same_function() {
    let sandbox = sandbox();
    let victim = compile_victim(&sandbox);
    let protected = sandbox.join("victim.protected");
    let native_image = fs::read(&victim).expect("read victim");
    let elf = Elf64::parse(&native_image).expect("parse victim");
    let matches = elf
        .find_functions_containing("sirus_marker_target")
        .expect("find target");
    assert_eq!(matches.len(), 1);
    let function = matches.first().copied().expect("target");
    let function_offset = usize::try_from(
        elf.vaddr_to_offset(function.value)
            .expect("function offset"),
    )
    .expect("offset");
    let function_end = function_offset
        .checked_add(usize::try_from(function.size).expect("function size"))
        .expect("function end");
    let begin = unique_marker(&native_image, &elf, function_offset);
    let end = unique_marker(&native_image, &elf, function_end);

    let output = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_sirus")))
        .arg("protect")
        .arg("--input")
        .arg(&victim)
        .arg("--output")
        .arg(&protected)
        .arg("--marker-begin")
        .arg(hex(&begin))
        .arg("--marker-end")
        .arg(hex(&end))
        .arg("--seed")
        .arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .output()
        .expect("protect markers");
    assert!(
        output.status.success(),
        "protect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut permissions = fs::metadata(&protected).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&protected, permissions).expect("chmod");
    for arguments in [["9", "2"], ["2", "9"], ["0", "0"], ["1234", "567"]] {
        let native = run(&victim, &arguments);
        let protected = run(&protected, &arguments);
        assert_eq!(native.stdout, protected.stdout, "arguments {arguments:?}");
    }
    let protected_image = fs::read(&protected).expect("read protected");
    let protected_elf = Elf64::parse(&protected_image).expect("parse protected");
    assert!(protected_elf.find_section(".sirus").is_some());
    let patch_offset = usize::try_from(
        protected_elf
            .vaddr_to_offset(function.value)
            .expect("patch offset"),
    )
    .expect("patch offset");
    assert_eq!(protected_image.get(patch_offset), Some(&0xe9));
    drop(fs::remove_dir_all(sandbox));
}
