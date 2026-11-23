//! Real-loader acceptance test: inject an unused RX segment and execute the
//! resulting dynamically linked PIE. This proves the relocated program-header
//! table, `PT_PHDR`, and appended segment are accepted by the kernel and `ld.so`.

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration test uses assertion panics and fixed fixture offsets"
)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use sirus_binfmt::elf::{Elf64, Injection, inject};

#[test]
fn injected_system_binary_still_runs() {
    let source = if std::path::Path::new("/bin/true").exists() {
        "/bin/true"
    } else if std::path::Path::new("/usr/bin/true").exists() {
        "/usr/bin/true"
    } else {
        return;
    };
    let original = fs::read(source).expect("read true");
    let elf = Elf64::parse(&original).expect("parse true");
    assert!(matches!(elf.header().kind, 2 | 3));
    let vm_vaddr = elf
        .next_free_vaddr(0x1000)
        .expect("next vaddr")
        .checked_add(0x1000)
        .expect("gap");
    let vm_bytes = [0x90_u8; 0x200];
    let result = inject(&original, &Injection::new(&vm_bytes, vm_vaddr, 0, 0)).expect("inject");
    let reparsed = Elf64::parse(&result.image).expect("reparse");
    assert!(reparsed.find_section(".sirus").is_some());
    assert!(
        reparsed
            .executable_segment(vm_vaddr, u64::try_from(vm_bytes.len()).expect("vm size"))
            .is_some()
    );

    let path = env::temp_dir().join(format!("sirus-injected-true-{}", std::process::id()));
    fs::write(&path, &result.image).expect("write protected true");
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod");
    let status = Command::new(&path)
        .status()
        .expect("execute protected true");
    drop(fs::remove_file(&path));
    assert!(status.success(), "loader rejected injected image: {status}");
}
