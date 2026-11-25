//! Unsafe, no_std runtime checks for the optional hardened tier.
//!
//! This module is copied verbatim into the generated hardened VM. It never
//! allocates and imports no symbols.

/// Verifies the generated code range against an expected FNV-1a hash.
///
/// The caller supplies linker-resolved addresses. The range is bounded before
/// it is read, and the expected value is loaded volatile so the post-link patch
/// is not constant-folded.
#[inline]
#[must_use]
pub fn verify_code(start: usize, end: usize, expected: usize) -> bool {
    let Some(length) = end.checked_sub(start) else {
        return false;
    };
    if length == 0 || length > 0x0010_0000 {
        return false;
    }
    // SAFETY: `start..start+length` is the generated text range bounded by
    // linker markers, and `expected` points at the patched static.
    let bytes = unsafe { core::slice::from_raw_parts(start as *const u8, length) };
    // SAFETY: the generated wrapper passes the address of an aligned u64.
    let expected = unsafe { core::ptr::read_volatile(expected as *const u64) };
    code_hash(bytes) == expected
}

/// Word-wise FNV-1a over generated code bytes.
#[inline]
fn code_hash(bytes: &[u8]) -> u64 {
    let mut value = 0xcbf2_9ce4_8422_2325_u64;
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(<[u8; 8]>::try_from(chunk).unwrap_or([0; 8]));
        value ^= word;
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for byte in chunks.remainder() {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value
}

/// Reads the x86-64 time-stamp counter.
#[inline]
#[must_use]
pub fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: RDTSC is available on every x86-64 CPU and has no memory
        // preconditions.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Serializes prior loads against later timing reads.
#[inline]
pub fn lfence() {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: LFENCE is an unprivileged serializing instruction.
        unsafe { core::arch::x86_64::_mm_lfence() }
    }
}

/// Returns whether the current process is being traced or debugged.
#[inline]
#[must_use]
pub fn debugger_present() -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        linux_debugger_present()
    }
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        windows_debugger_present()
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "windows")
    )))]
    {
        true
    }
}

/// Returns whether CPUID reports a hypervisor present bit.
#[inline]
#[must_use]
pub fn hypervisor_present() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let leaf = core::arch::x86_64::__cpuid(1);
        leaf.ecx & (1 << 31) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Returns true when the elapsed cycle count is within `maximum`.
///
/// The caller must pass a start value from [`rdtsc`] and should call
/// [`lfence`] immediately before timing the end.
#[inline]
#[must_use]
pub fn timing_ok(start: u64, maximum: u64) -> bool {
    lfence();
    let end = rdtsc();
    lfence();
    end.wrapping_sub(start) <= maximum
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn linux_debugger_present() -> bool {
    let path = b"/proc/self/status\0";
    // SAFETY: the path pointer is a NUL-terminated static, and the syscall
    // arguments follow the Linux x86-64 ABI.
    let descriptor = unsafe { syscall4(257, (-100_i64) as u64, path.as_ptr() as u64, 0, 0) };
    if descriptor < 0 {
        return true;
    }
    let descriptor = u64::try_from(descriptor).unwrap_or(0);
    let mut buffer = [0_u8; 512];
    // SAFETY: `buffer` is a live stack array; its pointer and length are valid
    // for the duration of the syscall.
    let length = unsafe {
        syscall3(
            0,
            descriptor,
            buffer.as_mut_ptr() as u64,
            u64::try_from(buffer.len()).unwrap_or(0),
        )
    };
    // SAFETY: closing a descriptor returned by openat is safe; failure is
    // intentionally ignored.
    let _ = unsafe { syscall3(3, descriptor, 0, 0) };
    if length <= 0 {
        return true;
    }
    let length = usize::try_from(length).unwrap_or(0);
    let Some(bytes) = buffer.get(..length) else {
        return true;
    };
    let needle = b"TracerPid:";
    let mut index = 0_usize;
    while index.saturating_add(needle.len()) <= bytes.len() {
        let Some(window) = bytes.get(index..index.saturating_add(needle.len())) else {
            return true;
        };
        if window == needle {
            return tracer_pid_nonzero(bytes, index.saturating_add(needle.len()));
        }
        index = index.saturating_add(1);
    }
    true
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn tracer_pid_nonzero(bytes: &[u8], mut index: usize) -> bool {
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b':' || byte == b' ' || byte == b'\t' {
            index = index.saturating_add(1);
        } else {
            break;
        }
    }
    let mut saw_digit = false;
    while let Some(byte) = bytes.get(index).copied() {
        if byte.is_ascii_digit() {
            saw_digit = true;
            if byte != b'0' {
                return true;
            }
            index = index.saturating_add(1);
        } else {
            break;
        }
    }
    !saw_digit
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[inline]
unsafe fn syscall3(number: u64, first: u64, second: u64, third: u64) -> i64 {
    let result: i64;
    // SAFETY: the caller supplies valid syscall arguments; clobbers are
    // declared and the stack is not used by the sequence.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") i64::try_from(number).unwrap_or(i64::MAX) => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    result
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[inline]
unsafe fn syscall4(number: u64, first: u64, second: u64, third: u64, fourth: u64) -> i64 {
    let result: i64;
    // SAFETY: the caller supplies valid syscall arguments; clobbers are
    // declared and the stack is not used by the sequence.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") i64::try_from(number).unwrap_or(i64::MAX) => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            in("r10") fourth,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    result
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fn windows_debugger_present() -> bool {
    let peb: *const u8;
    // SAFETY: on Windows x86-64, GS:[0x60] points at the current PEB.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags)
        );
    }
    if peb.is_null() {
        return true;
    }
    // SAFETY: PEB.BeingDebugged is at offset 2. The PEB is process-owned and
    // remains mapped for the lifetime of the process.
    let being_debugged = unsafe { core::ptr::read_volatile(peb.add(2)) };
    if being_debugged != 0 {
        return true;
    }
    // SAFETY: PEB.NtGlobalFlag is at offset 0xBC on x86-64. Debug heap flags
    // 0x70 are set by common native debuggers.
    let global_flags = unsafe { core::ptr::read_volatile(peb.add(0xbc).cast::<u32>()) };
    global_flags & 0x70 != 0
}

#[cfg(test)]
mod tests {
    use super::{debugger_present, hypervisor_present, lfence, rdtsc, timing_ok};

    #[test]
    fn runtime_checks_are_callable() {
        let _ = debugger_present();
        let _ = hypervisor_present();
        lfence();
        let start = rdtsc();
        let _ = rdtsc();
        lfence();
        assert!(timing_ok(start, u64::MAX));
    }
}
