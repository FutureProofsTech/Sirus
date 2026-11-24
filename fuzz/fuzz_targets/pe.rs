#![no_main]
use libfuzzer_sys::fuzz_target;
use sirus_binfmt::pe::{Pe64, append_executable_section};

fuzz_target!(|data: &[u8]| {
    if let Ok(pe) = Pe64::parse(data) {
        let _ = pe.sections().len();
        let _ = pe.symbols();
        let _ = pe.find_section(".text");
        let _ = pe.find_functions_containing("main");
        let _ = pe.section_for_rva(0x1000, 0x20);
        let _ = pe.read_rva(0x1000, 0x20);
        let _ = pe.find_pattern_unique(b"");
        let _ = append_executable_section(data, &[0x90; 8]);
    }
});
