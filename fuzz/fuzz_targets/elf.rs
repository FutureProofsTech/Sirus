#![no_main]
use libfuzzer_sys::fuzz_target;
use sirus_binfmt::elf::Elf64;

fuzz_target!(|data: &[u8]| {
    if let Ok(elf) = Elf64::parse(data) {
        let _ = elf.section_headers().len();
        let _ = elf.program_headers().len();
        let _ = elf.symbols();
        let _ = elf.functions();
        let _ = elf.undefined_symbols();
        let _ = elf.find_functions_containing("main");
        let _ = elf.find_pattern_unique(b"");
        let _ = elf.max_load_end();
        let _ = elf.next_free_vaddr(0x1000);
        let _ = elf.read_vaddr(0x1000, 0x20);
    }
});
