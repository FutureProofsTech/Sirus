//! Host-only introspection used by `sirus harden-check`.
//!
//! This module is not copied into generated VMs.

/// Returns the current thread's debug registers when the host exposes them.
///
/// Linux user mode cannot read another thread's debug registers without a
/// ptrace relationship, so this returns `None` there.
#[inline]
#[must_use]
pub fn debug_registers() -> Option<[u64; 4]> {
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        windows_debug_registers()
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
    {
        None
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
#[repr(C, align(16))]
struct ContextBuffer([u8; 1232]);

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> isize;
    fn GetThreadContext(thread: isize, context: *mut u8) -> i32;
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fn windows_debug_registers() -> Option<[u64; 4]> {
    const CONTEXT_DEBUG_REGISTERS_AMD64: u32 = 0x0010_0010;
    let mut buffer = ContextBuffer([0_u8; 1232]);
    if let Some(flags) = buffer.0.get_mut(0x30..0x34) {
        flags.copy_from_slice(&CONTEXT_DEBUG_REGISTERS_AMD64.to_le_bytes());
    }
    // SAFETY: the pseudo-handle is valid for the current thread and the context
    // buffer is correctly sized and 16-byte aligned for x86-64 Windows.
    let result = unsafe { GetThreadContext(GetCurrentThread(), buffer.0.as_mut_ptr()) };
    if result == 0 {
        return None;
    }
    let mut registers = [0_u64; 4];
    let mut index = 0_usize;
    while index < registers.len() {
        let offset = 0x48_usize.checked_add(index.checked_mul(8)?)?;
        let bytes = buffer.0.get(offset..offset.checked_add(8)?)?;
        let array = <[u8; 8]>::try_from(bytes).ok()?;
        if let Some(slot) = registers.get_mut(index) {
            *slot = u64::from_le_bytes(array);
        }
        index = index.saturating_add(1);
    }
    Some(registers)
}
