//! ELF64 little-endian parsing and injection for x86-64.
//!
//! The parser is strict and allocates only header/symbol vectors. The injector
//! is append-only: existing bytes are never relocated, the program-header table
//! is moved to a new mapped page, one RX VM segment is added, and section
//! metadata is regenerated for tooling.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::{
    FormatError, Result, align_up, align_up_usize, read_u16, read_u32, read_u64, write_u16,
    write_u32, write_u64,
};

/// ELF magic bytes.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// ELF class for 64-bit objects.
pub const ELFCLASS64: u8 = 2;
/// ELF little-endian encoding.
pub const ELFDATA2LSB: u8 = 1;
/// Executable file type.
pub const ET_EXEC: u16 = 2;
/// Position-independent executable file type.
pub const ET_DYN: u16 = 3;
/// x86-64 machine id.
pub const EM_X86_64: u16 = 62;
/// Loadable segment.
pub const PT_LOAD: u32 = 1;
/// Program-header table segment.
pub const PT_PHDR: u32 = 6;
/// Executable permission.
pub const PF_X: u32 = 1;
/// Writable permission.
pub const PF_W: u32 = 2;
/// Read permission.
pub const PF_R: u32 = 4;
/// Allocated section.
pub const SHF_ALLOC: u64 = 2;
/// Executable section.
pub const SHF_EXECINSTR: u64 = 4;
/// Progbits section type.
pub const SHT_PROGBITS: u32 = 1;
/// Symbol table section type.
pub const SHT_SYMTAB: u32 = 2;
/// String table section type.
pub const SHT_STRTAB: u32 = 3;
/// No-bits section type.
pub const SHT_NOBITS: u32 = 8;
/// Dynamic symbol table section type.
pub const SHT_DYNSYM: u32 = 11;
/// Relocation entries with addends.
pub const SHT_RELA: u32 = 4;
/// Relocation entries without addends.
pub const SHT_REL: u32 = 9;
/// Object symbol type.
pub const STT_OBJECT: u8 = 1;
/// Function symbol type.
pub const STT_FUNC: u8 = 2;
/// Undefined section index.
pub const SHN_UNDEF: u16 = 0;
/// Standard ELF64 header size.
pub const ELF64_HEADER_SIZE: usize = 64;
/// Standard ELF64 program header size.
pub const ELF64_PHDR_SIZE: usize = 56;
/// Standard ELF64 section header size.
pub const ELF64_SHDR_SIZE: usize = 64;
/// Maximum accepted program headers.
pub const MAX_PROGRAM_HEADERS: u16 = 1024;
/// Maximum accepted section headers.
pub const MAX_SECTION_HEADERS: u16 = 4096;
/// Maximum accepted symbols.
pub const MAX_SYMBOLS: usize = 200_000;

/// Parsed ELF64 header.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElfHeader {
    /// Object type.
    pub kind: u16,
    /// Machine id.
    pub machine: u16,
    /// Entry virtual address.
    pub entry: u64,
    /// Program-header table file offset.
    pub phoff: u64,
    /// Section-header table file offset.
    pub shoff: u64,
    /// Processor flags.
    pub flags: u32,
    /// ELF header size.
    pub ehsize: u16,
    /// Program-header entry size.
    pub phentsize: u16,
    /// Program-header count.
    pub phnum: u16,
    /// Section-header entry size.
    pub shentsize: u16,
    /// Section-header count.
    pub shnum: u16,
    /// Section-name string table index.
    pub shstrndx: u16,
}

/// Parsed program header.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgramHeader {
    /// Segment type.
    pub p_type: u32,
    /// Segment flags.
    pub p_flags: u32,
    /// File offset.
    pub p_offset: u64,
    /// Virtual address.
    pub p_vaddr: u64,
    /// Physical address.
    pub p_paddr: u64,
    /// File size.
    pub p_filesz: u64,
    /// Memory size.
    pub p_memsz: u64,
    /// Alignment.
    pub p_align: u64,
}

/// Parsed section header.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionHeader {
    /// Name offset in the section-name string table.
    pub sh_name: u32,
    /// Section type.
    pub sh_type: u32,
    /// Section flags.
    pub sh_flags: u64,
    /// Virtual address.
    pub sh_addr: u64,
    /// File offset.
    pub sh_offset: u64,
    /// Section size.
    pub sh_size: u64,
    /// Linked section index.
    pub sh_link: u32,
    /// Extra information.
    pub sh_info: u32,
    /// Address alignment.
    pub sh_addralign: u64,
    /// Entry size.
    pub sh_entsize: u64,
}

/// Parsed function or object symbol.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolEntry<'a> {
    /// Symbol name.
    pub name: &'a str,
    /// Symbol value (virtual address in a linked image).
    pub value: u64,
    /// Symbol size.
    pub size: u64,
    /// Symbol type (lower nibble of `st_info`).
    pub kind: u8,
    /// Symbol binding (upper nibble of `st_info`).
    pub bind: u8,
    /// Defining section index.
    pub section: u16,
}

/// Parsed ELF64 image.
#[derive(Clone, Debug)]
pub struct Elf64<'a> {
    data: &'a [u8],
    header: ElfHeader,
    phdrs: Vec<ProgramHeader>,
    sections: Vec<SectionHeader>,
}

impl<'a> Elf64<'a> {
    /// Parses and validates an ELF64 little-endian x86-64 image.
    #[allow(clippy::too_many_lines)]
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < ELF64_HEADER_SIZE {
            return Err(FormatError::Malformed);
        }
        let magic = data.get(0..4).ok_or(FormatError::Malformed)?;
        if magic != ELF_MAGIC {
            return Err(FormatError::Unsupported);
        }
        let class = data.get(4).copied().ok_or(FormatError::Malformed)?;
        let encoding = data.get(5).copied().ok_or(FormatError::Malformed)?;
        let version = data.get(6).copied().ok_or(FormatError::Malformed)?;
        if class != ELFCLASS64 || encoding != ELFDATA2LSB || version != 1 {
            return Err(FormatError::Unsupported);
        }
        let kind = read_u16(data, 16)?;
        let machine = read_u16(data, 18)?;
        if kind != ET_EXEC && kind != ET_DYN {
            return Err(FormatError::Unsupported);
        }
        if machine != EM_X86_64 {
            return Err(FormatError::Unsupported);
        }
        let header = ElfHeader {
            kind,
            machine,
            entry: read_u64(data, 24)?,
            phoff: read_u64(data, 32)?,
            shoff: read_u64(data, 40)?,
            flags: read_u32(data, 48)?,
            ehsize: read_u16(data, 52)?,
            phentsize: read_u16(data, 54)?,
            phnum: read_u16(data, 56)?,
            shentsize: read_u16(data, 58)?,
            shnum: read_u16(data, 60)?,
            shstrndx: read_u16(data, 62)?,
        };
        if usize::from(header.ehsize) < ELF64_HEADER_SIZE {
            return Err(FormatError::Malformed);
        }
        if header.phnum > MAX_PROGRAM_HEADERS || header.shnum > MAX_SECTION_HEADERS {
            return Err(FormatError::TooManyItems);
        }
        if header.phnum == u16::MAX || header.shnum == u16::MAX {
            return Err(FormatError::Unsupported);
        }
        if header.phnum > 0 && usize::from(header.phentsize) < ELF64_PHDR_SIZE {
            return Err(FormatError::Malformed);
        }
        if header.shnum > 0 && usize::from(header.shentsize) < ELF64_SHDR_SIZE {
            return Err(FormatError::Malformed);
        }
        if header.shnum == 0 && header.shoff != 0 {
            return Err(FormatError::Unsupported);
        }
        if header.shnum > 0 && header.shstrndx >= header.shnum {
            return Err(FormatError::Malformed);
        }

        let phdrs = parse_program_headers(data, &header)?;
        let sections = parse_section_headers(data, &header)?;
        let image = Self {
            data,
            header,
            phdrs,
            sections,
        };
        image.validate_segments()?;
        Ok(image)
    }

    /// Returns the parsed header.
    #[inline]
    #[must_use]
    pub const fn header(&self) -> &ElfHeader {
        &self.header
    }

    /// Returns all program headers.
    #[inline]
    #[must_use]
    pub fn program_headers(&self) -> &[ProgramHeader] {
        &self.phdrs
    }

    /// Returns all section headers.
    #[inline]
    #[must_use]
    pub fn section_headers(&self) -> &[SectionHeader] {
        &self.sections
    }

    /// Returns the raw input.
    #[inline]
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns a section name.
    #[inline]
    #[must_use]
    pub fn section_name(&self, index: usize) -> Option<&'a str> {
        let header = self.sections.get(index)?;
        let table = self.sections.get(usize::from(self.header.shstrndx))?;
        if table.sh_type != SHT_STRTAB {
            return None;
        }
        let name_offset = usize::try_from(header.sh_name).ok()?;
        let table_start = usize::try_from(table.sh_offset).ok()?;
        let table_size = usize::try_from(table.sh_size).ok()?;
        let table_end = table_start.checked_add(table_size)?;
        let table_data = self.data.get(table_start..table_end)?;
        c_string(table_data, name_offset)
    }

    /// Finds a section by name.
    #[inline]
    #[must_use]
    pub fn find_section(&self, name: &str) -> Option<(usize, SectionHeader)> {
        let mut index = 0_usize;
        while index < self.sections.len() {
            if self.section_name(index) == Some(name) {
                return self
                    .sections
                    .get(index)
                    .copied()
                    .map(|section| (index, section));
            }
            index = index.saturating_add(1);
        }
        None
    }

    /// Returns the end of the highest mapped load segment.
    #[inline]
    #[must_use]
    pub fn max_load_end(&self) -> u64 {
        let mut end = 0_u64;
        for program in &self.phdrs {
            if program.p_type == PT_LOAD {
                let candidate = program.p_vaddr.saturating_add(program.p_memsz);
                if candidate > end {
                    end = candidate;
                }
            }
        }
        end
    }

    /// Returns a page-aligned address after every mapped segment.
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn next_free_vaddr(&self, alignment: u64) -> Result<u64> {
        align_up(self.max_load_end(), alignment)
    }

    /// Maps a virtual address to a file offset.
    #[inline]
    #[must_use]
    pub fn vaddr_to_offset(&self, address: u64) -> Option<u64> {
        for program in &self.phdrs {
            if program.p_type != PT_LOAD || program.p_offset == 0 && program.p_filesz == 0 {
                continue;
            }
            let start = program.p_vaddr;
            let end = program.p_vaddr.checked_add(program.p_filesz)?;
            if address >= start && address < end {
                let relative = address.checked_sub(start)?;
                let offset = program.p_offset.checked_add(relative)?;
                if usize::try_from(offset).ok()? <= self.data.len() {
                    return Some(offset);
                }
            }
        }
        None
    }

    /// Maps a file offset to a virtual address.
    #[inline]
    #[must_use]
    pub fn offset_to_vaddr(&self, offset: u64) -> Option<u64> {
        for program in &self.phdrs {
            if program.p_type != PT_LOAD {
                continue;
            }
            let start = program.p_offset;
            let end = program.p_offset.checked_add(program.p_filesz)?;
            if offset >= start && offset < end {
                let relative = offset.checked_sub(start)?;
                let address = program.p_vaddr.checked_add(relative)?;
                if usize::try_from(offset).ok()? <= self.data.len() {
                    return Some(address);
                }
            }
        }
        None
    }

    /// Returns the executable segment containing a virtual range.
    #[inline]
    #[must_use]
    pub fn executable_segment(&self, address: u64, size: u64) -> Option<&ProgramHeader> {
        let end = address.checked_add(size)?;
        for program in &self.phdrs {
            if program.p_type != PT_LOAD || (program.p_flags & PF_X) == 0 {
                continue;
            }
            let file_end = program.p_vaddr.checked_add(program.p_filesz)?;
            let memory_end = program.p_vaddr.checked_add(program.p_memsz)?;
            if address >= program.p_vaddr && end <= file_end && end <= memory_end {
                return Some(program);
            }
        }
        None
    }

    /// Returns a loaded segment containing a file range.
    #[inline]
    #[must_use]
    pub fn file_segment(&self, offset: u64, size: u64) -> Option<&ProgramHeader> {
        let end = offset.checked_add(size)?;
        for program in &self.phdrs {
            if program.p_type != PT_LOAD {
                continue;
            }
            let file_end = program.p_offset.checked_add(program.p_filesz)?;
            if offset >= program.p_offset && end <= file_end {
                return Some(program);
            }
        }
        None
    }

    /// Reads bytes at a virtual address.
    #[inline]
    #[must_use]
    pub fn read_vaddr(&self, address: u64, size: u64) -> Option<&'a [u8]> {
        let offset = usize::try_from(self.vaddr_to_offset(address)?).ok()?;
        let length = usize::try_from(size).ok()?;
        self.data.get(offset..offset.checked_add(length)?)
    }

    /// Returns all defined function and object symbols, deduplicated across
    /// `.symtab` and `.dynsym`.
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn symbols(&self) -> Result<Vec<SymbolEntry<'a>>> {
        let mut symbols = Vec::new();
        let mut index = 0_usize;
        while index < self.sections.len() {
            let Some(section) = self.sections.get(index) else {
                break;
            };
            if section.sh_type == SHT_SYMTAB || section.sh_type == SHT_DYNSYM {
                self.collect_symbols(section, &mut symbols)?;
            }
            index = index.saturating_add(1);
        }
        symbols.sort_unstable_by(compare_symbols);
        symbols.dedup_by(|left, right| {
            left.value == right.value
                && left.size == right.size
                && left.name == right.name
                && left.section == right.section
        });
        Ok(symbols)
    }

    /// Returns all function symbols.
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn functions(&self) -> Result<Vec<SymbolEntry<'a>>> {
        let mut functions = Vec::new();
        for symbol in self.symbols()? {
            if symbol.kind == STT_FUNC {
                functions.push(symbol);
            }
        }
        Ok(functions)
    }

    /// Finds defined symbols whose names contain a substring.
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn find_symbols_containing(&self, needle: &str) -> Result<Vec<SymbolEntry<'a>>> {
        let mut output = Vec::new();
        for symbol in self.symbols()? {
            if symbol.name.contains(needle) {
                output.push(symbol);
            }
        }
        Ok(output)
    }

    /// Returns names of undefined symbols.
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn undefined_symbols(&self) -> Result<Vec<&'a str>> {
        let mut output = Vec::new();
        let mut index = 0_usize;
        while index < self.sections.len() {
            let Some(section) = self.sections.get(index) else {
                break;
            };
            if section.sh_type == SHT_SYMTAB || section.sh_type == SHT_DYNSYM {
                self.collect_undefined(section, &mut output)?;
            }
            index = index.saturating_add(1);
        }
        Ok(output)
    }

    fn collect_undefined(&self, section: &SectionHeader, output: &mut Vec<&'a str>) -> Result<()> {
        let entry_size = if section.sh_entsize == 0 {
            24
        } else {
            usize::try_from(section.sh_entsize).map_err(|_| FormatError::Malformed)?
        };
        if entry_size < 24 || section.sh_size % u64::try_from(entry_size).unwrap_or(1) != 0 {
            return Err(FormatError::Malformed);
        }
        let table_offset = usize::try_from(section.sh_offset).map_err(|_| FormatError::Bounds)?;
        let table_size = usize::try_from(section.sh_size).map_err(|_| FormatError::Bounds)?;
        let string_index = usize::try_from(section.sh_link).map_err(|_| FormatError::Malformed)?;
        let string_section = self
            .sections
            .get(string_index)
            .ok_or(FormatError::Malformed)?;
        if string_section.sh_type != SHT_STRTAB {
            return Err(FormatError::Malformed);
        }
        let string_offset =
            usize::try_from(string_section.sh_offset).map_err(|_| FormatError::Bounds)?;
        let string_size =
            usize::try_from(string_section.sh_size).map_err(|_| FormatError::Bounds)?;
        let strings = self
            .data
            .get(
                string_offset
                    ..string_offset
                        .checked_add(string_size)
                        .ok_or(FormatError::Bounds)?,
            )
            .ok_or(FormatError::Bounds)?;
        let count = table_size / entry_size;
        let mut symbol_index = 0_usize;
        while symbol_index < count {
            let offset = table_offset
                .checked_add(
                    symbol_index
                        .checked_mul(entry_size)
                        .ok_or(FormatError::Bounds)?,
                )
                .ok_or(FormatError::Bounds)?;
            let name_offset = read_u32(self.data, offset)?;
            let section_index =
                read_u16(self.data, offset.checked_add(6).ok_or(FormatError::Bounds)?)?;
            if section_index == SHN_UNDEF {
                let name = c_string(strings, usize::try_from(name_offset).unwrap_or(usize::MAX))
                    .unwrap_or("");
                if !name.is_empty() {
                    output.push(name);
                }
            }
            symbol_index = symbol_index.saturating_add(1);
        }
        Ok(())
    }

    /// Returns whether the image contains relocation sections.
    #[inline]
    #[must_use]
    pub fn has_relocations(&self) -> bool {
        for section in &self.sections {
            if (section.sh_type == SHT_RELA || section.sh_type == SHT_REL) && section.sh_size > 0 {
                return true;
            }
        }
        false
    }

    fn collect_symbols(
        &self,
        section: &SectionHeader,
        output: &mut Vec<SymbolEntry<'a>>,
    ) -> Result<()> {
        if section.sh_type == SHT_NOBITS {
            return Ok(());
        }
        let entry_size = if section.sh_entsize == 0 {
            ELF64_SHDR_SIZE.saturating_sub(40)
        } else {
            usize::try_from(section.sh_entsize).map_err(|_| FormatError::Malformed)?
        };
        if entry_size < 24 || section.sh_size % u64::try_from(entry_size).unwrap_or(1) != 0 {
            return Err(FormatError::Malformed);
        }
        let table_offset = usize::try_from(section.sh_offset).map_err(|_| FormatError::Bounds)?;
        let table_size = usize::try_from(section.sh_size).map_err(|_| FormatError::Bounds)?;
        let table_end = table_offset
            .checked_add(table_size)
            .ok_or(FormatError::Bounds)?;
        if table_end > self.data.len() {
            return Err(FormatError::Bounds);
        }
        let string_index = usize::try_from(section.sh_link).map_err(|_| FormatError::Malformed)?;
        let string_section = self
            .sections
            .get(string_index)
            .ok_or(FormatError::Malformed)?;
        if string_section.sh_type != SHT_STRTAB {
            return Err(FormatError::Malformed);
        }
        let string_offset =
            usize::try_from(string_section.sh_offset).map_err(|_| FormatError::Bounds)?;
        let string_size =
            usize::try_from(string_section.sh_size).map_err(|_| FormatError::Bounds)?;
        let string_end = string_offset
            .checked_add(string_size)
            .ok_or(FormatError::Bounds)?;
        if string_end > self.data.len() {
            return Err(FormatError::Bounds);
        }
        let strings = self
            .data
            .get(string_offset..string_end)
            .ok_or(FormatError::Bounds)?;
        let count = table_size / entry_size;
        if output.len().saturating_add(count) > MAX_SYMBOLS {
            return Err(FormatError::TooManyItems);
        }
        let mut symbol_index = 0_usize;
        while symbol_index < count {
            let offset = table_offset
                .checked_add(
                    symbol_index
                        .checked_mul(entry_size)
                        .ok_or(FormatError::Bounds)?,
                )
                .ok_or(FormatError::Bounds)?;
            let name_offset = read_u32(self.data, offset)?;
            let info = self
                .data
                .get(offset.checked_add(4).ok_or(FormatError::Bounds)?)
                .copied()
                .ok_or(FormatError::Bounds)?;
            let section_index =
                read_u16(self.data, offset.checked_add(6).ok_or(FormatError::Bounds)?)?;
            let value = read_u64(self.data, offset.checked_add(8).ok_or(FormatError::Bounds)?)?;
            let size = read_u64(
                self.data,
                offset.checked_add(16).ok_or(FormatError::Bounds)?,
            )?;
            let kind = info & 0x0f;
            if (kind == STT_FUNC || kind == STT_OBJECT) && section_index != SHN_UNDEF && size > 0 {
                let name = c_string(strings, usize::try_from(name_offset).unwrap_or(usize::MAX))
                    .unwrap_or("");
                if !name.is_empty() {
                    output.push(SymbolEntry {
                        name,
                        value,
                        size,
                        kind,
                        bind: info >> 4,
                        section: section_index,
                    });
                }
            }
            symbol_index = symbol_index.saturating_add(1);
        }
        Ok(())
    }

    /// Finds exactly one function by name.
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn find_function(&self, name: &str) -> Result<SymbolEntry<'a>> {
        let functions = self.functions()?;
        let mut found: Option<SymbolEntry<'a>> = None;
        for function in functions {
            if function.name == name {
                if found.is_some() {
                    return Err(FormatError::Ambiguous);
                }
                found = Some(function);
            }
        }
        found.ok_or(FormatError::NotFound)
    }

    /// Finds functions whose names contain a substring.
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn find_functions_containing(&self, needle: &str) -> Result<Vec<SymbolEntry<'a>>> {
        let mut output = Vec::new();
        for function in self.functions()? {
            if function.name.contains(needle) {
                output.push(function);
            }
        }
        Ok(output)
    }

    /// Finds exactly one occurrence of a byte pattern.
    #[inline]
    ///
    /// # Errors
    ///
    /// Returns a typed [`FormatError`] when the input or request is invalid.
    pub fn find_pattern_unique(&self, pattern: &[u8]) -> Result<usize> {
        if pattern.is_empty() {
            return Err(FormatError::Malformed);
        }
        let mut found: Option<usize> = None;
        let mut index = 0_usize;
        while index < self.data.len() {
            let candidate = self.data.get(index..index.saturating_add(pattern.len()));
            if candidate == Some(pattern) {
                if found.is_some() {
                    return Err(FormatError::Ambiguous);
                }
                found = Some(index);
            }
            index = index.saturating_add(1);
        }
        found.ok_or(FormatError::NotFound)
    }

    fn validate_segments(&self) -> Result<()> {
        for program in &self.phdrs {
            if program.p_filesz > 0 {
                let start = usize::try_from(program.p_offset).map_err(|_| FormatError::Bounds)?;
                let size = usize::try_from(program.p_filesz).map_err(|_| FormatError::Bounds)?;
                let end = start.checked_add(size).ok_or(FormatError::Bounds)?;
                if end > self.data.len() {
                    return Err(FormatError::Bounds);
                }
            }
            if program.p_type == PT_LOAD {
                if program.p_memsz < program.p_filesz {
                    return Err(FormatError::Malformed);
                }
                if program.p_align > 1 {
                    if !program.p_align.is_power_of_two() {
                        return Err(FormatError::BadAlignment);
                    }
                    if program.p_offset % program.p_align != program.p_vaddr % program.p_align {
                        return Err(FormatError::BadAlignment);
                    }
                }
            }
        }
        for section in &self.sections {
            if section.sh_type != SHT_NOBITS && section.sh_size > 0 {
                let start = usize::try_from(section.sh_offset).map_err(|_| FormatError::Bounds)?;
                let size = usize::try_from(section.sh_size).map_err(|_| FormatError::Bounds)?;
                let end = start.checked_add(size).ok_or(FormatError::Bounds)?;
                if end > self.data.len() {
                    return Err(FormatError::Bounds);
                }
            }
            if section.sh_addralign > 1 && !section.sh_addralign.is_power_of_two() {
                return Err(FormatError::BadAlignment);
            }
        }
        Ok(())
    }
}

fn parse_program_headers(data: &[u8], header: &ElfHeader) -> Result<Vec<ProgramHeader>> {
    let count = usize::from(header.phnum);
    let entry_size = usize::from(header.phentsize);
    let table_offset = usize::try_from(header.phoff).map_err(|_| FormatError::Bounds)?;
    let table_end = table_offset
        .checked_add(count.checked_mul(entry_size).ok_or(FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    if table_end > data.len() {
        return Err(FormatError::Bounds);
    }
    let mut output = Vec::with_capacity(count);
    let mut index = 0_usize;
    while index < count {
        let offset = table_offset
            .checked_add(index.checked_mul(entry_size).ok_or(FormatError::Bounds)?)
            .ok_or(FormatError::Bounds)?;
        output.push(ProgramHeader {
            p_type: read_u32(data, offset)?,
            p_flags: read_u32(data, offset.checked_add(4).ok_or(FormatError::Bounds)?)?,
            p_offset: read_u64(data, offset.checked_add(8).ok_or(FormatError::Bounds)?)?,
            p_vaddr: read_u64(data, offset.checked_add(16).ok_or(FormatError::Bounds)?)?,
            p_paddr: read_u64(data, offset.checked_add(24).ok_or(FormatError::Bounds)?)?,
            p_filesz: read_u64(data, offset.checked_add(32).ok_or(FormatError::Bounds)?)?,
            p_memsz: read_u64(data, offset.checked_add(40).ok_or(FormatError::Bounds)?)?,
            p_align: read_u64(data, offset.checked_add(48).ok_or(FormatError::Bounds)?)?,
        });
        index = index.saturating_add(1);
    }
    Ok(output)
}

fn parse_section_headers(data: &[u8], header: &ElfHeader) -> Result<Vec<SectionHeader>> {
    let count = usize::from(header.shnum);
    if count == 0 {
        return Ok(Vec::new());
    }
    let entry_size = usize::from(header.shentsize);
    let table_offset = usize::try_from(header.shoff).map_err(|_| FormatError::Bounds)?;
    let table_end = table_offset
        .checked_add(count.checked_mul(entry_size).ok_or(FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    if table_end > data.len() {
        return Err(FormatError::Bounds);
    }
    let mut output = Vec::with_capacity(count);
    let mut index = 0_usize;
    while index < count {
        let offset = table_offset
            .checked_add(index.checked_mul(entry_size).ok_or(FormatError::Bounds)?)
            .ok_or(FormatError::Bounds)?;
        output.push(SectionHeader {
            sh_name: read_u32(data, offset)?,
            sh_type: read_u32(data, offset.checked_add(4).ok_or(FormatError::Bounds)?)?,
            sh_flags: read_u64(data, offset.checked_add(8).ok_or(FormatError::Bounds)?)?,
            sh_addr: read_u64(data, offset.checked_add(16).ok_or(FormatError::Bounds)?)?,
            sh_offset: read_u64(data, offset.checked_add(24).ok_or(FormatError::Bounds)?)?,
            sh_size: read_u64(data, offset.checked_add(32).ok_or(FormatError::Bounds)?)?,
            sh_link: read_u32(data, offset.checked_add(40).ok_or(FormatError::Bounds)?)?,
            sh_info: read_u32(data, offset.checked_add(44).ok_or(FormatError::Bounds)?)?,
            sh_addralign: read_u64(data, offset.checked_add(48).ok_or(FormatError::Bounds)?)?,
            sh_entsize: read_u64(data, offset.checked_add(56).ok_or(FormatError::Bounds)?)?,
        });
        index = index.saturating_add(1);
    }
    Ok(output)
}

fn compare_symbols(left: &SymbolEntry<'_>, right: &SymbolEntry<'_>) -> Ordering {
    left.value
        .cmp(&right.value)
        .then_with(|| left.name.cmp(right.name))
        .then_with(|| left.size.cmp(&right.size))
}

fn c_string(table: &[u8], offset: usize) -> Option<&str> {
    if offset >= table.len() {
        return None;
    }
    let remainder = table.get(offset..)?;
    let mut length = 0_usize;
    while length < remainder.len() {
        if remainder.get(length).copied()? == 0 {
            break;
        }
        length = length.saturating_add(1);
    }
    core::str::from_utf8(remainder.get(..length)?).ok()
}

/// Sets a relative `E9` jump at `from_va`, optionally preserving CET `endbr64`.
///
/// Returns the virtual address at which the five-byte patch was written.
///
/// # Errors
///
/// Returns a typed [`FormatError`] when the input or request is invalid.
#[inline]
pub fn patch_relative_jump(
    image: &mut [u8],
    from_va: u64,
    to_va: u64,
    preserve_endbr: bool,
) -> Result<u64> {
    let (patch_va, file_offset) = {
        let elf = Elf64::parse(image)?;
        if elf.executable_segment(from_va, 5).is_none() {
            return Err(FormatError::Bounds);
        }
        let mut patch = from_va;
        if preserve_endbr {
            if let Some(bytes) = elf.read_vaddr(from_va, 4) {
                if bytes == [0xf3, 0x0f, 0x1e, 0xfa] {
                    patch = from_va.checked_add(4).ok_or(FormatError::Bounds)?;
                    if elf.executable_segment(patch, 5).is_none() {
                        return Err(FormatError::Bounds);
                    }
                }
            }
        }
        let offset = elf.vaddr_to_offset(patch).ok_or(FormatError::Bounds)?;
        (patch, offset)
    };
    let next = patch_va.checked_add(5).ok_or(FormatError::Bounds)?;
    let difference = if to_va >= next {
        i128::from(to_va.checked_sub(next).ok_or(FormatError::Bounds)?)
    } else {
        -i128::from(next.checked_sub(to_va).ok_or(FormatError::Bounds)?)
    };
    let displacement = i32::try_from(difference).map_err(|_| FormatError::JumpOutOfRange)?;
    let offset = usize::try_from(file_offset).map_err(|_| FormatError::Bounds)?;
    let target = image
        .get_mut(offset..offset.checked_add(5).ok_or(FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    if let Some(slot) = target.get_mut(0) {
        *slot = 0xe9;
    }
    let bytes = displacement.to_le_bytes();
    let mut index = 0_usize;
    while index < 4 {
        if let (Some(slot), Some(byte)) =
            (target.get_mut(index.saturating_add(1)), bytes.get(index))
        {
            *slot = *byte;
        }
        index = index.saturating_add(1);
    }
    Ok(patch_va)
}

/// Overwrites a virtual range with caller-supplied bytes.
///
/// # Errors
///
/// Returns a typed [`FormatError`] when the input or request is invalid.
#[inline]
pub fn overwrite_vaddr(image: &mut [u8], address: u64, bytes: &[u8]) -> Result<()> {
    let elf = Elf64::parse(image)?;
    let offset = usize::try_from(elf.vaddr_to_offset(address).ok_or(FormatError::Bounds)?)
        .map_err(|_| FormatError::Bounds)?;
    let size = bytes.len();
    let target = image
        .get_mut(offset..offset.checked_add(size).ok_or(FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    target.copy_from_slice(bytes);
    Ok(())
}

/// Reads a virtual range without parsing the file again for each call.
#[inline]
#[must_use]
pub fn read_vaddr(image: &[u8], address: u64, size: u64) -> Option<&[u8]> {
    let elf = Elf64::parse(image).ok()?;
    elf.read_vaddr(address, size)
}

/// Description of a VM image to inject.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct Injection<'a> {
    /// VM image bytes, exactly as produced by the freestanding link step.
    pub vm_bytes: &'a [u8],
    /// Exact virtual address at which the VM image was linked.
    pub vm_vaddr: u64,
    /// Offset of the encrypted payload inside the VM image.
    pub payload_offset: usize,
    /// Length of the encrypted payload.
    pub payload_len: usize,
}

impl<'a> Injection<'a> {
    /// Creates an injection description.
    #[inline]
    #[must_use]
    pub const fn new(
        vm_bytes: &'a [u8],
        vm_vaddr: u64,
        payload_offset: usize,
        payload_len: usize,
    ) -> Self {
        Self {
            vm_bytes,
            vm_vaddr,
            payload_offset,
            payload_len,
        }
    }
}

/// Result of an ELF injection.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectionResult {
    /// Complete protected image.
    pub image: Vec<u8>,
    /// File offset of the VM segment.
    pub vm_offset: u64,
    /// Virtual address of the VM segment.
    pub vm_vaddr: u64,
    /// File offset of the payload within the image.
    pub payload_offset: u64,
    /// Virtual address of the payload.
    pub payload_vaddr: u64,
    /// Virtual address of the relocated program-header table.
    pub phdr_vaddr: u64,
    /// Index of the `.sirus` section header.
    pub sirus_section: Option<usize>,
    /// Index of the `.sirus.payload` section header.
    pub payload_section: Option<usize>,
}

/// Injects a linked VM image into an ELF64 executable.
///
/// Existing file bytes are preserved. A new program-header table is appended and
/// mapped read-only, the VM is appended and mapped read-execute, and section
/// metadata is regenerated without changing existing section data.
#[allow(clippy::too_many_lines)]
#[inline]
///
/// # Errors
///
/// Returns a typed [`FormatError`] when the input or request is invalid.
pub fn inject(original: &[u8], injection: &Injection<'_>) -> Result<InjectionResult> {
    let elf = Elf64::parse(original)?;
    if elf.find_section(".sirus").is_some() {
        return Err(FormatError::AlreadyProtected);
    }
    if injection.vm_bytes.is_empty() {
        return Err(FormatError::Malformed);
    }
    let vm_len = injection.vm_bytes.len();
    let payload_end = injection
        .payload_offset
        .checked_add(injection.payload_len)
        .ok_or(FormatError::Bounds)?;
    if payload_end > vm_len {
        return Err(FormatError::PayloadOutsideVm);
    }
    if injection.vm_vaddr % 0x1000 != 0 {
        return Err(FormatError::BadAlignment);
    }
    if injection.vm_vaddr < elf.max_load_end() {
        return Err(FormatError::Overlap);
    }
    let vm_end = injection
        .vm_vaddr
        .checked_add(u64::try_from(vm_len).map_err(|_| FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    let phdr_vaddr = align_up(vm_end, 0x1000)?;
    for program in elf.program_headers() {
        if program.p_type != PT_LOAD {
            continue;
        }
        let existing_end = program
            .p_vaddr
            .checked_add(program.p_memsz)
            .ok_or(FormatError::Bounds)?;
        let overlaps_vm = injection.vm_vaddr < existing_end && program.p_vaddr < vm_end;
        let overlaps_phdr = phdr_vaddr < existing_end
            && program.p_vaddr < phdr_vaddr.checked_add(0x1000).ok_or(FormatError::Bounds)?;
        if overlaps_vm || overlaps_phdr {
            return Err(FormatError::Overlap);
        }
    }

    let has_phdr = elf
        .program_headers()
        .iter()
        .any(|program| program.p_type == PT_PHDR);
    let extra = if has_phdr { 2_usize } else { 3_usize };
    let new_phnum = usize::from(elf.header().phnum)
        .checked_add(extra)
        .ok_or(FormatError::TooManyItems)?;
    if new_phnum > usize::from(u16::MAX) {
        return Err(FormatError::TooManyItems);
    }
    let phdr_table_size = new_phnum
        .checked_mul(ELF64_PHDR_SIZE)
        .ok_or(FormatError::Bounds)?;
    let phdr_file_offset = align_up_usize(original.len(), 0x1000)?;
    let vm_file_offset = align_up_usize(
        phdr_file_offset
            .checked_add(phdr_table_size)
            .ok_or(FormatError::Bounds)?,
        0x1000,
    )?;

    let mut new_phdrs: Vec<ProgramHeader> = Vec::with_capacity(new_phnum);
    if !has_phdr {
        new_phdrs.push(ProgramHeader {
            p_type: PT_PHDR,
            p_flags: PF_R,
            p_offset: u64::try_from(phdr_file_offset).map_err(|_| FormatError::Bounds)?,
            p_vaddr: phdr_vaddr,
            p_paddr: phdr_vaddr,
            p_filesz: u64::try_from(phdr_table_size).map_err(|_| FormatError::Bounds)?,
            p_memsz: u64::try_from(phdr_table_size).map_err(|_| FormatError::Bounds)?,
            p_align: 8,
        });
    }
    for program in elf.program_headers() {
        let mut copy = *program;
        if copy.p_type == PT_PHDR {
            copy.p_flags = PF_R;
            copy.p_offset = u64::try_from(phdr_file_offset).map_err(|_| FormatError::Bounds)?;
            copy.p_vaddr = phdr_vaddr;
            copy.p_paddr = phdr_vaddr;
            copy.p_filesz = u64::try_from(phdr_table_size).map_err(|_| FormatError::Bounds)?;
            copy.p_memsz = u64::try_from(phdr_table_size).map_err(|_| FormatError::Bounds)?;
            copy.p_align = 8;
        }
        new_phdrs.push(copy);
    }
    new_phdrs.push(ProgramHeader {
        p_type: PT_LOAD,
        p_flags: PF_R,
        p_offset: u64::try_from(phdr_file_offset).map_err(|_| FormatError::Bounds)?,
        p_vaddr: phdr_vaddr,
        p_paddr: phdr_vaddr,
        p_filesz: u64::try_from(phdr_table_size).map_err(|_| FormatError::Bounds)?,
        p_memsz: u64::try_from(phdr_table_size).map_err(|_| FormatError::Bounds)?,
        p_align: 0x1000,
    });
    new_phdrs.push(ProgramHeader {
        p_type: PT_LOAD,
        p_flags: PF_R | PF_X,
        p_offset: u64::try_from(vm_file_offset).map_err(|_| FormatError::Bounds)?,
        p_vaddr: injection.vm_vaddr,
        p_paddr: injection.vm_vaddr,
        p_filesz: u64::try_from(vm_len).map_err(|_| FormatError::Bounds)?,
        p_memsz: u64::try_from(vm_len).map_err(|_| FormatError::Bounds)?,
        p_align: 0x1000,
    });
    if new_phdrs.len() != new_phnum {
        return Err(FormatError::Malformed);
    }
    let phdr_bytes = serialize_program_headers(&new_phdrs)?;

    let old_sections = elf.section_headers();
    let old_shstrndx = usize::from(elf.header().shstrndx);
    let has_sections = !old_sections.is_empty();
    let old_shstrtab = if has_sections && old_shstrndx != 0 {
        old_sections
            .get(old_shstrndx)
            .copied()
            .filter(|section| section.sh_type == SHT_STRTAB)
    } else {
        None
    };
    let old_names = if let Some(section) = old_shstrtab {
        let start = usize::try_from(section.sh_offset).map_err(|_| FormatError::Bounds)?;
        let size = usize::try_from(section.sh_size).map_err(|_| FormatError::Bounds)?;
        original
            .get(start..start.checked_add(size).ok_or(FormatError::Bounds)?)
            .ok_or(FormatError::Bounds)?
    } else {
        &[]
    };
    let mut new_names = Vec::with_capacity(old_names.len().saturating_add(32));
    new_names.extend_from_slice(old_names);
    if new_names.last() != Some(&0) {
        new_names.push(0);
    }
    let sirus_name_offset = new_names.len();
    new_names.extend_from_slice(b".sirus\0");
    let payload_name_offset = new_names.len();
    new_names.extend_from_slice(b".sirus.payload\0");

    let mut new_sections: Vec<SectionHeader> =
        Vec::with_capacity(old_sections.len().saturating_add(3));
    let new_shstrndx: u16;
    if has_sections {
        new_sections.extend_from_slice(old_sections);
        if old_shstrtab.is_some() {
            let shstrtab_section = new_sections
                .get_mut(old_shstrndx)
                .ok_or(FormatError::SectionTableInvalid)?;
            shstrtab_section.sh_type = SHT_STRTAB;
            shstrtab_section.sh_flags = 0;
            shstrtab_section.sh_addr = 0;
            shstrtab_section.sh_offset = 0;
            shstrtab_section.sh_size = 0;
            shstrtab_section.sh_link = 0;
            shstrtab_section.sh_info = 0;
            shstrtab_section.sh_addralign = 1;
            shstrtab_section.sh_entsize = 0;
            new_shstrndx = u16::try_from(old_shstrndx).map_err(|_| FormatError::TooManyItems)?;
        } else {
            let index = new_sections.len();
            new_sections.push(SectionHeader {
                sh_type: SHT_STRTAB,
                sh_addralign: 1,
                ..SectionHeader::default()
            });
            new_shstrndx = u16::try_from(index).map_err(|_| FormatError::TooManyItems)?;
        }
        new_sections.push(SectionHeader {
            sh_name: u32::try_from(sirus_name_offset).map_err(|_| FormatError::Bounds)?,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC | SHF_EXECINSTR,
            sh_addr: injection.vm_vaddr,
            sh_offset: u64::try_from(vm_file_offset).map_err(|_| FormatError::Bounds)?,
            sh_size: u64::try_from(vm_len).map_err(|_| FormatError::Bounds)?,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0x1000,
            sh_entsize: 0,
        });
        new_sections.push(SectionHeader {
            sh_name: u32::try_from(payload_name_offset).map_err(|_| FormatError::Bounds)?,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC,
            sh_addr: injection
                .vm_vaddr
                .checked_add(
                    u64::try_from(injection.payload_offset).map_err(|_| FormatError::Bounds)?,
                )
                .ok_or(FormatError::Bounds)?,
            sh_offset: u64::try_from(
                vm_file_offset
                    .checked_add(injection.payload_offset)
                    .ok_or(FormatError::Bounds)?,
            )
            .map_err(|_| FormatError::Bounds)?,
            sh_size: u64::try_from(injection.payload_len).map_err(|_| FormatError::Bounds)?,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
    } else {
        new_sections.push(SectionHeader::default());
        new_sections.push(SectionHeader {
            sh_type: SHT_STRTAB,
            sh_addralign: 1,
            ..SectionHeader::default()
        });
        new_sections.push(SectionHeader {
            sh_name: u32::try_from(sirus_name_offset).map_err(|_| FormatError::Bounds)?,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC | SHF_EXECINSTR,
            sh_addr: injection.vm_vaddr,
            sh_offset: u64::try_from(vm_file_offset).map_err(|_| FormatError::Bounds)?,
            sh_size: u64::try_from(vm_len).map_err(|_| FormatError::Bounds)?,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0x1000,
            sh_entsize: 0,
        });
        new_sections.push(SectionHeader {
            sh_name: u32::try_from(payload_name_offset).map_err(|_| FormatError::Bounds)?,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC,
            sh_addr: injection
                .vm_vaddr
                .checked_add(
                    u64::try_from(injection.payload_offset).map_err(|_| FormatError::Bounds)?,
                )
                .ok_or(FormatError::Bounds)?,
            sh_offset: u64::try_from(
                vm_file_offset
                    .checked_add(injection.payload_offset)
                    .ok_or(FormatError::Bounds)?,
            )
            .map_err(|_| FormatError::Bounds)?,
            sh_size: u64::try_from(injection.payload_len).map_err(|_| FormatError::Bounds)?,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
        new_shstrndx = 1;
    }
    let new_section_indices = if has_sections {
        let count = new_sections.len();
        let sirus = count
            .checked_sub(2)
            .ok_or(FormatError::SectionTableInvalid)?;
        let payload = count
            .checked_sub(1)
            .ok_or(FormatError::SectionTableInvalid)?;
        Some((sirus, payload))
    } else {
        Some((2, 3))
    };
    if new_sections.len() > usize::from(u16::MAX) {
        return Err(FormatError::TooManyItems);
    }
    let section_count_u16 =
        u16::try_from(new_sections.len()).map_err(|_| FormatError::TooManyItems)?;

    let after_vm = vm_file_offset
        .checked_add(vm_len)
        .ok_or(FormatError::Bounds)?;
    let new_strtab_offset = align_up_usize(after_vm, 8)?;
    let new_shoff = align_up_usize(
        new_strtab_offset
            .checked_add(new_names.len())
            .ok_or(FormatError::Bounds)?,
        8,
    )?;
    let new_shentsize = ELF64_SHDR_SIZE;
    let new_shstrtab_section = new_sections
        .get_mut(usize::from(new_shstrndx))
        .ok_or(FormatError::SectionTableInvalid)?;
    new_shstrtab_section.sh_offset =
        u64::try_from(new_strtab_offset).map_err(|_| FormatError::Bounds)?;
    new_shstrtab_section.sh_size =
        u64::try_from(new_names.len()).map_err(|_| FormatError::Bounds)?;
    let section_bytes = serialize_section_headers(&new_sections)?;

    let total_size = new_shoff
        .checked_add(section_bytes.len())
        .ok_or(FormatError::Bounds)?;
    if total_size > 512 * 1024 * 1024 {
        return Err(FormatError::TooManyItems);
    }
    let mut output = Vec::with_capacity(total_size);
    output.extend_from_slice(original);
    output.resize(phdr_file_offset, 0);
    output.extend_from_slice(&phdr_bytes);
    output.resize(vm_file_offset, 0);
    output.extend_from_slice(injection.vm_bytes);
    output.resize(new_strtab_offset, 0);
    output.extend_from_slice(&new_names);
    output.resize(new_shoff, 0);
    output.extend_from_slice(&section_bytes);

    write_u64(
        &mut output,
        32,
        u64::try_from(phdr_file_offset).map_err(|_| FormatError::Bounds)?,
    )?;
    write_u64(
        &mut output,
        40,
        u64::try_from(new_shoff).map_err(|_| FormatError::Bounds)?,
    )?;
    write_u16(
        &mut output,
        54,
        u16::try_from(ELF64_PHDR_SIZE).map_err(|_| FormatError::Bounds)?,
    )?;
    write_u16(&mut output, 56, new_phnum_u16(new_phnum)?)?;
    write_u16(
        &mut output,
        58,
        u16::try_from(new_shentsize).map_err(|_| FormatError::Bounds)?,
    )?;
    write_u16(&mut output, 60, section_count_u16)?;
    write_u16(&mut output, 62, new_shstrndx)?;

    let reparsed = Elf64::parse(&output)?;
    if reparsed.program_headers().len() != new_phnum
        || reparsed.section_headers().len() != usize::from(section_count_u16)
        || reparsed.find_section(".sirus").is_none()
        || reparsed.find_section(".sirus.payload").is_none()
    {
        return Err(FormatError::Malformed);
    }

    let payload_offset = vm_file_offset
        .checked_add(injection.payload_offset)
        .ok_or(FormatError::Bounds)?;
    let payload_vaddr = injection
        .vm_vaddr
        .checked_add(u64::try_from(injection.payload_offset).map_err(|_| FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    let (sirus_section, payload_section) = match new_section_indices {
        Some((sirus, payload)) => (Some(sirus), Some(payload)),
        None => (None, None),
    };
    Ok(InjectionResult {
        image: output,
        vm_offset: u64::try_from(vm_file_offset).map_err(|_| FormatError::Bounds)?,
        vm_vaddr: injection.vm_vaddr,
        payload_offset: u64::try_from(payload_offset).map_err(|_| FormatError::Bounds)?,
        payload_vaddr,
        phdr_vaddr,
        sirus_section,
        payload_section,
    })
}

fn new_phnum_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| FormatError::TooManyItems)
}

fn serialize_program_headers(headers: &[ProgramHeader]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(
        headers
            .len()
            .checked_mul(ELF64_PHDR_SIZE)
            .ok_or(FormatError::Bounds)?,
    );
    for header in headers {
        bytes.resize(bytes.len().saturating_add(ELF64_PHDR_SIZE), 0);
        let offset = bytes.len().saturating_sub(ELF64_PHDR_SIZE);
        write_u32(&mut bytes, offset, header.p_type)?;
        write_u32(&mut bytes, offset + 4, header.p_flags)?;
        write_u64(&mut bytes, offset + 8, header.p_offset)?;
        write_u64(&mut bytes, offset + 16, header.p_vaddr)?;
        write_u64(&mut bytes, offset + 24, header.p_paddr)?;
        write_u64(&mut bytes, offset + 32, header.p_filesz)?;
        write_u64(&mut bytes, offset + 40, header.p_memsz)?;
        write_u64(&mut bytes, offset + 48, header.p_align)?;
    }
    Ok(bytes)
}

fn serialize_section_headers(sections: &[SectionHeader]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(
        sections
            .len()
            .checked_mul(ELF64_SHDR_SIZE)
            .ok_or(FormatError::Bounds)?,
    );
    for section in sections {
        bytes.resize(bytes.len().saturating_add(ELF64_SHDR_SIZE), 0);
        let offset = bytes.len().saturating_sub(ELF64_SHDR_SIZE);
        write_u32(&mut bytes, offset, section.sh_name)?;
        write_u32(&mut bytes, offset + 4, section.sh_type)?;
        write_u64(&mut bytes, offset + 8, section.sh_flags)?;
        write_u64(&mut bytes, offset + 16, section.sh_addr)?;
        write_u64(&mut bytes, offset + 24, section.sh_offset)?;
        write_u64(&mut bytes, offset + 32, section.sh_size)?;
        write_u32(&mut bytes, offset + 40, section.sh_link)?;
        write_u32(&mut bytes, offset + 44, section.sh_info)?;
        write_u64(&mut bytes, offset + 48, section.sh_addralign)?;
        write_u64(&mut bytes, offset + 56, section.sh_entsize)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{Elf64, Injection, PT_LOAD, PT_PHDR, inject, overwrite_vaddr, patch_relative_jump};
    use crate::FormatError;
    use alloc::vec;
    use alloc::vec::Vec;

    fn synthetic_elf() -> Vec<u8> {
        let mut data = vec![0_u8; 0x2000];
        data[0..4].copy_from_slice(&super::ELF_MAGIC);
        data[4] = super::ELFCLASS64;
        data[5] = super::ELFDATA2LSB;
        data[6] = 1;
        data[16..18].copy_from_slice(&super::ET_DYN.to_le_bytes());
        data[18..20].copy_from_slice(&super::EM_X86_64.to_le_bytes());
        data[20..24].copy_from_slice(&1_u32.to_le_bytes());
        data[24..32].copy_from_slice(&0x1000_u64.to_le_bytes());
        data[32..40].copy_from_slice(&64_u64.to_le_bytes());
        data[40..48].copy_from_slice(&0x800_u64.to_le_bytes());
        data[52..54].copy_from_slice(&64_u16.to_le_bytes());
        data[54..56].copy_from_slice(&56_u16.to_le_bytes());
        data[56..58].copy_from_slice(&2_u16.to_le_bytes());
        data[58..60].copy_from_slice(&64_u16.to_le_bytes());
        data[60..62].copy_from_slice(&3_u16.to_le_bytes());
        data[62..64].copy_from_slice(&1_u16.to_le_bytes());
        // PHDR at 64
        data[64..68].copy_from_slice(&PT_PHDR.to_le_bytes());
        data[68..72].copy_from_slice(&4_u32.to_le_bytes());
        data[72..80].copy_from_slice(&64_u64.to_le_bytes());
        data[80..88].copy_from_slice(&64_u64.to_le_bytes());
        data[88..96].copy_from_slice(&64_u64.to_le_bytes());
        data[96..104].copy_from_slice(&112_u64.to_le_bytes());
        data[104..112].copy_from_slice(&112_u64.to_le_bytes());
        data[112..120].copy_from_slice(&8_u64.to_le_bytes());
        // LOAD at 120
        data[120..124].copy_from_slice(&PT_LOAD.to_le_bytes());
        data[124..128].copy_from_slice(&5_u32.to_le_bytes());
        data[128..136].copy_from_slice(&0_u64.to_le_bytes());
        data[136..144].copy_from_slice(&0_u64.to_le_bytes());
        data[144..152].copy_from_slice(&0_u64.to_le_bytes());
        data[152..160].copy_from_slice(&0x2000_u64.to_le_bytes());
        data[160..168].copy_from_slice(&0x2000_u64.to_le_bytes());
        data[168..176].copy_from_slice(&0x1000_u64.to_le_bytes());
        // section table at 0x800: null, .shstrtab, .text
        data[0x800..0x804].copy_from_slice(&0_u32.to_le_bytes());
        let mut shoff = 0x800_usize;
        // null section
        shoff += 64;
        // shstrtab at 0x900
        data[0x900..0x911].copy_from_slice(b"\0.shstrtab\0.text\0");
        data[shoff..shoff + 4].copy_from_slice(&1_u32.to_le_bytes());
        data[shoff + 4..shoff + 8].copy_from_slice(&super::SHT_STRTAB.to_le_bytes());
        data[shoff + 24..shoff + 32].copy_from_slice(&0x900_u64.to_le_bytes());
        data[shoff + 32..shoff + 40].copy_from_slice(&17_u64.to_le_bytes());
        data[shoff + 48..shoff + 56].copy_from_slice(&1_u64.to_le_bytes());
        shoff += 64;
        data[shoff..shoff + 4].copy_from_slice(&11_u32.to_le_bytes());
        data[shoff + 4..shoff + 8].copy_from_slice(&super::SHT_PROGBITS.to_le_bytes());
        data[shoff + 8..shoff + 16]
            .copy_from_slice(&(super::SHF_ALLOC | super::SHF_EXECINSTR).to_le_bytes());
        data[shoff + 16..shoff + 24].copy_from_slice(&0x1000_u64.to_le_bytes());
        data[shoff + 24..shoff + 32].copy_from_slice(&0x1000_u64.to_le_bytes());
        data[shoff + 32..shoff + 40].copy_from_slice(&16_u64.to_le_bytes());
        data[shoff + 48..shoff + 56].copy_from_slice(&16_u64.to_le_bytes());
        data[0x1000..0x1010]
            .copy_from_slice(b"\x48\x89\xf8\x48\x01\xf0\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90");
        data
    }

    #[test]
    fn parses_synthetic_elf() {
        let data = synthetic_elf();
        let elf = Elf64::parse(&data).expect("parse");
        assert_eq!(elf.header().kind, super::ET_DYN);
        assert_eq!(elf.program_headers().len(), 2);
        assert_eq!(elf.section_headers().len(), 3);
        assert_eq!(elf.find_section(".text").map(|value| value.0), Some(2));
        assert_eq!(elf.vaddr_to_offset(0x1000), Some(0x1000));
        assert!(elf.executable_segment(0x1000, 4).is_some());
    }

    #[test]
    fn injects_vm_segment_and_sections() {
        let data = synthetic_elf();
        let vm_vaddr = 0x10_000_u64;
        let vm = vec![0x90_u8; 0x200];
        let injection = Injection {
            vm_bytes: &vm,
            vm_vaddr,
            payload_offset: 0x100,
            payload_len: 0x80,
        };
        let result = inject(&data, &injection).expect("inject");
        let elf = Elf64::parse(&result.image).expect("reparse");
        assert!(elf.find_section(".sirus").is_some());
        assert!(elf.find_section(".sirus.payload").is_some());
        assert!(elf.executable_segment(vm_vaddr, 0x200).is_some());
        assert_eq!(elf.program_headers().len(), 4);
        assert_eq!(elf.header().phnum, 4);
        assert_eq!(result.vm_vaddr, vm_vaddr);
        assert_eq!(result.vm_offset % 0x1000, 0);
        assert_eq!(
            elf.vaddr_to_offset(result.payload_vaddr),
            Some(result.payload_offset)
        );
    }

    #[test]
    fn patches_endbr_and_jump() {
        let mut data = synthetic_elf();
        data[0x1000..0x1004].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);
        let patch = patch_relative_jump(&mut data, 0x1000, 0x1080, true).expect("patch");
        assert_eq!(patch, 0x1004);
        let bytes = data.get(0x1004..0x1009).expect("bytes");
        assert_eq!(bytes.first(), Some(&0xe9));
    }
    #[test]
    fn rejects_malformed_headers() {
        let base = synthetic_elf();
        let mut cases = Vec::new();
        cases.push(Vec::new());
        let mut wrong_magic = base.clone();
        wrong_magic[0] = 0;
        cases.push(wrong_magic);
        let mut wrong_class = base.clone();
        wrong_class[4] = 1;
        cases.push(wrong_class);
        let mut wrong_machine = base.clone();
        wrong_machine[18..20].copy_from_slice(&3_u16.to_le_bytes());
        cases.push(wrong_machine);
        let mut wrong_kind = base.clone();
        wrong_kind[16..18].copy_from_slice(&1_u16.to_le_bytes());
        cases.push(wrong_kind);
        let mut bad_phoff = base.clone();
        bad_phoff[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        cases.push(bad_phoff);
        let mut invalid_section_offset = base.clone();
        invalid_section_offset[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        cases.push(invalid_section_offset);
        let mut huge_phnum = base.clone();
        huge_phnum[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        cases.push(huge_phnum);
        let mut zero_phentsize = base.clone();
        zero_phentsize[54..56].copy_from_slice(&0_u16.to_le_bytes());
        cases.push(zero_phentsize);
        let mut no_section_entry_size = base;
        no_section_entry_size[58..60].copy_from_slice(&0_u16.to_le_bytes());
        cases.push(no_section_entry_size);
        for case in cases {
            assert!(Elf64::parse(&case).is_err());
        }
    }

    #[test]
    fn reports_symbol_and_section_queries() {
        let data = synthetic_elf();
        let elf = Elf64::parse(&data).expect("parse");
        assert_eq!(elf.section_name(2), Some(".text"));
        assert_eq!(elf.section_name(99), None);
        assert_eq!(elf.functions().expect("functions").len(), 0);
        assert_eq!(elf.symbols().expect("symbols").len(), 0);
        assert_eq!(elf.undefined_symbols().expect("undefined").len(), 0);
        assert_eq!(elf.find_function("missing"), Err(FormatError::NotFound));
        assert_eq!(
            elf.find_functions_containing("anything")
                .expect("contains")
                .len(),
            0
        );
        assert_eq!(elf.offset_to_vaddr(0x1000), Some(0x1000));
        assert_eq!(elf.offset_to_vaddr(0x1fff), Some(0x1fff));
        assert_eq!(elf.offset_to_vaddr(0x2000), None);
        assert_eq!(elf.read_vaddr(0x1000, 4).map(<[u8]>::len), Some(4));
        assert!(elf.read_vaddr(0x1fff, 4).is_none());
        assert!(elf.file_segment(0x1000, 4).is_some());
        assert!(!elf.has_relocations());
    }

    #[test]
    fn marker_and_patch_errors_are_typed() {
        let data = synthetic_elf();
        let elf = Elf64::parse(&data).expect("parse");
        assert_eq!(elf.find_pattern_unique(&[]), Err(FormatError::Malformed));
        assert_eq!(elf.find_pattern_unique(&[0]), Err(FormatError::Ambiguous));
        assert_eq!(
            elf.find_pattern_unique(b"missing-pattern"),
            Err(FormatError::NotFound)
        );
        let mut image = data.clone();
        assert!(patch_relative_jump(&mut image, 0x1000, 0x1_0000_0000, false).is_err());
        assert!(patch_relative_jump(&mut image, 0x2000, 0x1000, false).is_err());
        assert!(overwrite_vaddr(&mut image, 0x2000, &[0]).is_err());
    }

    #[test]
    fn inject_errors_are_typed() {
        let data = synthetic_elf();
        let vm = [0x90_u8; 0x20];
        assert_eq!(
            inject(&data, &Injection::new(&vm, 0x10_001, 0, 0)).err(),
            Some(FormatError::BadAlignment)
        );
        assert_eq!(
            inject(&data, &Injection::new(&vm, 0x1000, 0, 0)).err(),
            Some(FormatError::Overlap)
        );
        assert_eq!(
            inject(&data, &Injection::new(&vm, 0x10_000, 0x20, 0x10)).err(),
            Some(FormatError::PayloadOutsideVm)
        );
        assert_eq!(
            inject(&data, &Injection::new(&[], 0x10_000, 0, 0)).err(),
            Some(FormatError::Malformed)
        );
        let first = inject(&data, &Injection::new(&vm, 0x10_000, 0, 0)).expect("first");
        assert_eq!(
            inject(&first.image, &Injection::new(&vm, 0x20_000, 0, 0)).err(),
            Some(FormatError::AlreadyProtected)
        );
    }
    #[test]
    fn injection_creates_a_section_name_table_when_missing() {
        let mut data = synthetic_elf();
        data[62..64].copy_from_slice(&0_u16.to_le_bytes());
        let vm = [0x90_u8; 0x20];
        let result = inject(&data, &Injection::new(&vm, 0x10_000, 0, 0)).expect("inject");
        let elf = Elf64::parse(&result.image).expect("reparse");
        assert!(elf.find_section(".sirus").is_some());
        assert!(elf.find_section(".sirus.payload").is_some());
    }
    #[test]
    fn malformed_prefixes_and_mutations_fail_closed() {
        let base = synthetic_elf();
        let mut length = 0_usize;
        while length <= base.len() {
            if let Some(prefix) = base.get(..length) {
                drop(Elf64::parse(prefix));
            }
            length = length.saturating_add(7);
        }
        let mut state = 0x1234_5678_9abc_def0_u64;
        let mut round = 0_usize;
        while round < 512 {
            let mut mutated = base.clone();
            let mut flips = 0_usize;
            while flips < 4 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let index =
                    usize::try_from(state % u64::try_from(mutated.len()).unwrap_or(1)).unwrap_or(0);
                if let Some(byte) = mutated.get_mut(index) {
                    *byte ^= u8::try_from((state >> 32) & 0xff).unwrap_or(1);
                }
                flips = flips.saturating_add(1);
            }
            if let Ok(elf) = Elf64::parse(&mutated) {
                let _ = elf.find_section(".text");
                drop(elf.symbols());
                drop(elf.undefined_symbols());
                let _ = elf.max_load_end();
                let _ = elf.next_free_vaddr(0x1000);
            }
            round = round.saturating_add(1);
        }
    }
}
