//! Real end-to-end protection test: compile a victim, protect it, execute it,
//! compare against native, and exercise adversarial mutations.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "integration test uses assertion panics, fixed fixtures, and a linear scenario"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sirus_binfmt::elf::{Elf64, PF_W, PF_X, PT_LOAD};

const VICTIM: &str = r#"
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![forbid(unsafe_code)]

#[inline(never)]
fn sirus_demo_check(a: u64, b: u64) -> u64 {
    if a > b {
        a.wrapping_mul(3)
            .wrapping_add(b)
            ^ 0xa5a5_5a5a_1234_5678
    } else {
        (b ^ a).wrapping_add(0x1234_5678_9abc_def0)
    }
}

#[inline(never)]
fn sirus_demo_loop(a: u64, b: u64) -> u64 {
    let mut accumulator = a.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut index = 0_u64;
    let limit = b & 7;
    while index < limit {
        accumulator = accumulator.rotate_left(5) ^ a.wrapping_add(index);
        index = index.wrapping_add(1);
    }
    accumulator
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let first = arguments.next().and_then(|value| value.parse::<u64>().ok()).unwrap_or(7);
    let second = arguments.next().and_then(|value| value.parse::<u64>().ok()).unwrap_or(3);
    println!("{}", sirus_demo_check(first, second));
    println!("{}", sirus_demo_loop(first, second));
}
"#;

fn sandbox() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("sirus-e2e-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("create sandbox");
    path
}

fn rustc() -> String {
    std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned())
}

fn compile_victim(sandbox: &Path) -> PathBuf {
    let source = sandbox.join("victim.rs");
    let binary = sandbox.join("victim");
    fs::write(&source, VICTIM).expect("write victim");
    let output = Command::new(rustc())
        .arg("--edition=2021")
        .arg("-C")
        .arg("opt-level=2")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("debuginfo=0")
        .arg("-C")
        .arg("codegen-units=1")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("run rustc");
    assert!(
        output.status.success(),
        "victim compile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn make_executable(path: &Path) {
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod");
}

fn protected_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sirus"))
}

fn run_bounded(binary: &Path, arguments: &[&str], timeout: Duration) -> Output {
    let mut child = Command::new(binary)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn victim");
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().expect("collect victim output"),
            Ok(None) => {
                if start.elapsed() > timeout {
                    drop(child.kill());
                    drop(child.wait());
                    panic!("victim exceeded {timeout:?}");
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("wait failed: {error}"),
        }
    }
}

fn protect(input: &Path, output: &Path, seed: &str) -> Output {
    Command::new(protected_binary())
        .arg("protect")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .arg("--function-contains")
        .arg("sirus_demo_check")
        .arg("--function-contains")
        .arg("sirus_demo_loop")
        .arg("--seed")
        .arg(seed)
        .output()
        .expect("run protector")
}

fn protect_constant_time(input: &Path, output: &Path, seed: &str) -> Output {
    Command::new(protected_binary())
        .arg("protect")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .arg("--function-contains")
        .arg("sirus_demo_check")
        .arg("--function-contains")
        .arg("sirus_demo_loop")
        .arg("--seed")
        .arg(seed)
        .arg("--constant-time")
        .arg("--constant-time-passes")
        .arg("64")
        .output()
        .expect("run constant-time protector")
}

fn section_bytes(image: &[u8], name: &str) -> Vec<u8> {
    let elf = Elf64::parse(image).expect("parse protected");
    let section = elf
        .find_section(name)
        .map(|(_, section)| section)
        .expect("section present");
    let start = usize::try_from(section.sh_offset).expect("offset");
    let size = usize::try_from(section.sh_size).expect("size");
    image
        .get(start..start + size)
        .expect("section range")
        .to_vec()
}

#[test]
fn end_to_end_protection_and_adversarial_mutations() {
    let sandbox = sandbox();
    let victim = compile_victim(&sandbox);
    let protected = sandbox.join("victim.protected");
    let seed_a = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let seed_b = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    let result = protect(&victim, &protected, seed_a);
    assert!(
        result.status.success(),
        "protect failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let native_image = fs::read(&victim).expect("read victim");
    let protected_image = fs::read(&protected).expect("read protected");
    let elf = Elf64::parse(&protected_image).expect("parse protected");
    assert!(elf.find_section(".sirus").is_some());
    assert!(elf.find_section(".sirus.payload").is_some());
    let sirus_section = elf
        .find_section(".sirus")
        .map(|(_, section)| section)
        .expect("sirus section");
    let mut sirus_executable = false;
    for header in elf.program_headers() {
        if header.p_type != PT_LOAD {
            continue;
        }
        let start = header.p_vaddr;
        let end = header.p_vaddr.saturating_add(header.p_memsz);
        if sirus_section.sh_addr >= start && sirus_section.sh_addr < end {
            assert!(header.p_flags & PF_X != 0);
            assert_eq!(header.p_flags & PF_W, 0);
            sirus_executable = true;
        }
    }
    assert!(sirus_executable);

    let inspection = Command::new(protected_binary())
        .arg("inspect")
        .arg(&protected)
        .output()
        .expect("inspect protected");
    assert!(inspection.status.success());
    let inspection_text = String::from_utf8_lossy(&inspection.stdout);
    assert!(inspection_text.contains("protected=true"));
    assert!(inspection_text.contains("functions="));

    let arguments = ["7", "3"];
    let native_output = run_bounded(&victim, &arguments, Duration::from_secs(5));
    let protected_output = run_bounded(&protected, &arguments, Duration::from_secs(5));
    assert!(native_output.status.success());
    assert!(protected_output.status.success());
    assert_eq!(native_output.stdout, protected_output.stdout);
    for arguments in [["3", "7"], ["0", "0"], ["123456789", "5"]] {
        let native_output = run_bounded(&victim, &arguments, Duration::from_secs(5));
        let protected_output = run_bounded(&protected, &arguments, Duration::from_secs(5));
        assert_eq!(
            native_output.stdout, protected_output.stdout,
            "arguments {arguments:?}"
        );
    }
    let mut random = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..20 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let first_text = format!("{random}");
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let second_text = format!("{random}");
        let arguments = [first_text.as_str(), second_text.as_str()];
        let native_output = run_bounded(&victim, &arguments, Duration::from_secs(5));
        let protected_output = run_bounded(&protected, &arguments, Duration::from_secs(5));
        assert_eq!(
            native_output.stdout, protected_output.stdout,
            "random arguments {arguments:?}"
        );
    }

    let constant = sandbox.join("victim.constant");
    let constant_result = protect_constant_time(&victim, &constant, seed_a);
    assert!(
        constant_result.status.success(),
        "constant-time protect failed: {}",
        String::from_utf8_lossy(&constant_result.stderr)
    );
    for arguments in [["7", "3"], ["3", "7"], ["0", "0"], ["123456789", "5"]] {
        let native_output = run_bounded(&victim, &arguments, Duration::from_secs(5));
        let constant_output = run_bounded(&constant, &arguments, Duration::from_secs(10));
        assert_eq!(
            native_output.stdout, constant_output.stdout,
            "constant-time arguments {arguments:?}"
        );
    }

    let native_elf = Elf64::parse(&native_image).expect("parse native");
    let checks = native_elf
        .find_functions_containing("sirus_demo_check")
        .expect("find check");
    let check = checks.first().copied().expect("check symbol");
    assert_eq!(checks.len(), 1);
    let check_offset = usize::try_from(
        native_elf
            .vaddr_to_offset(check.value)
            .expect("check file offset"),
    )
    .expect("check offset");
    let original_check = native_image
        .get(check_offset..check_offset + usize::try_from(check.size).expect("check size"))
        .expect("check bytes")
        .to_vec();
    let protected_check = protected_image
        .get(check_offset..check_offset + 16)
        .expect("protected check bytes")
        .to_vec();
    let jump_offset = if protected_check.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) {
        4
    } else {
        0
    };
    assert_eq!(protected_check.get(jump_offset), Some(&0xe9));
    assert_ne!(protected_check, original_check);
    let mut changed = 0_usize;
    for (index, byte) in protected_check.iter().enumerate() {
        if original_check.get(index) != Some(byte) {
            changed += 1;
        }
    }
    assert!(changed >= 8, "original function body was not scrubbed");

    let second_protected = sandbox.join("victim.protected.b");
    let second = protect(&victim, &second_protected, seed_b);
    assert!(
        second.status.success(),
        "second protect failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_image = fs::read(&second_protected).expect("read second");
    let first_payload = section_bytes(&protected_image, ".sirus.payload");
    let second_payload = section_bytes(&second_image, ".sirus.payload");
    assert_ne!(first_payload.len(), 0);
    assert_ne!(second_payload.len(), 0);
    assert_ne!(first_payload, second_payload);

    let tampered_path = sandbox.join("tampered");
    let mut tampered = protected_image.clone();
    let payload_section = elf
        .find_section(".sirus.payload")
        .map(|(_, section)| section)
        .expect("payload section");
    let payload_offset = usize::try_from(payload_section.sh_offset).expect("payload offset");
    let tamper_index =
        payload_offset + usize::try_from(payload_section.sh_size).expect("payload size") / 2;
    if let Some(byte) = tampered.get_mut(tamper_index) {
        *byte ^= 0x80;
    }
    fs::write(&tampered_path, tampered).expect("write tampered");
    make_executable(&tampered_path);
    let tampered_output = run_bounded(&tampered_path, &arguments, Duration::from_secs(5));
    assert_ne!(tampered_output.stdout, native_output.stdout);

    let bypass_path = sandbox.join("bypass");
    let mut bypass = protected_image.clone();
    let bypass_offset = usize::try_from(
        Elf64::parse(&protected_image)
            .expect("parse protected")
            .vaddr_to_offset(check.value)
            .expect("check offset"),
    )
    .expect("offset");
    if let Some(slot) = bypass.get_mut(bypass_offset) {
        *slot = 0x31;
    }
    if let Some(slot) = bypass.get_mut(bypass_offset + 1) {
        *slot = 0xc0;
    }
    if let Some(slot) = bypass.get_mut(bypass_offset + 2) {
        *slot = 0xc3;
    }
    fs::write(&bypass_path, bypass).expect("write bypass");
    make_executable(&bypass_path);
    let bypass_output = run_bounded(&bypass_path, &arguments, Duration::from_secs(5));
    assert_ne!(bypass_output.stdout, native_output.stdout);

    drop(fs::remove_dir_all(sandbox));
}
