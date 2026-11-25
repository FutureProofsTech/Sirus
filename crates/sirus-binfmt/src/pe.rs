//! PE32+ / x86-64 parsing and append-only executable-section injection.
//!
//! This backend covers the Windows executable container. Parsing, COFF symbol
//! lookup, section addition, RVA mapping, checksum regeneration, and jump
//! patching are implemented. The Win64 VM runtime is verified under Wine for the
//! strict branch/leaf subset; native Windows loader validation is not claimed.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    FormatError, Result, align_up, align_up_usize, read_u16, read_u32, read_u64, write_u16,
    write_u32,
};

/// DOS header magic.
pub const DOS_MAGIC: [u8; 2] = *b"MZ";
/// PE signature.
pub const PE_MAGIC: [u8; 4] = [b'P', b'E', 0, 0];
/// AMD64 machine id.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// PE32+ optional header magic.
pub const PE32_PLUS_MAGIC: u16 = 0x020b;
/// Executable code characteristic.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// Executable memory characteristic.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Readable memory characteristic.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// Writable memory characteristic.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// DOS header offset to the PE header pointer.
const DOS_LFANEW_OFFSET: usize = 0x3c;
/// COFF header size.
const COFF_HEADER_SIZE: usize = 20;
/// Section header size.
const SECTION_HEADER_SIZE: usize = 40;
/// Fixed PE32+ optional header size before data directories.
const OPTIONAL_FIXED_SIZE: usize = 112;
/// Exception directory index.
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: u32 = 3;
/// Size of one x64 runtime-function entry.
const RUNTIME_FUNCTION_SIZE: usize = 12;
/// Maximum accepted sections.
const MAX_SECTIONS: u16 = 512;

/// Parsed COFF header fields.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoffHeader {
    /// Machine id.
    pub machine: u16,
    /// Number of sections.
    pub section_count: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// Symbol table file offset.
    pub symbol_table: u32,
    /// Number of symbols.
    pub symbol_count: u32,
    /// Optional header size.
    pub optional_size: u16,
    /// File characteristics.
    pub characteristics: u16,
}

/// One symbol from the COFF symbol table.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeSymbol {
    /// Symbol name.
    pub name: String,
    /// Relative virtual address.
    pub rva: u32,
    /// Inferred byte size within its section.
    pub size: u32,
    /// One-based section index.
    pub section: u16,
    /// COFF type field.
    pub kind: u16,
    /// COFF storage class.
    pub storage_class: u8,
}

/// Parsed PE32+ optional header fields used by Sirus.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionalHeader {
    /// Entry point RVA.
    pub entry_rva: u32,
    /// Preferred image base.
    pub image_base: u64,
    /// Section alignment.
    pub section_alignment: u32,
    /// File alignment.
    pub file_alignment: u32,
    /// Size of the mapped image.
    pub size_of_image: u32,
    /// Size of all headers.
    pub size_of_headers: u32,
    /// PE checksum.
    pub checksum: u32,
    /// Subsystem.
    pub subsystem: u16,
    /// DLL characteristics.
    pub dll_characteristics: u16,
    /// Number of data directories.
    pub directory_count: u32,
}

/// Parsed section.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    /// Eight-byte name.
    pub name: [u8; 8],
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Raw file size.
    pub raw_size: u32,
    /// Raw file offset.
    pub raw_offset: u32,
    /// Relocation table offset.
    pub relocation_offset: u32,
    /// Line number table offset.
    pub line_offset: u32,
    /// Relocation count.
    pub relocation_count: u16,
    /// Line number count.
    pub line_count: u16,
    /// Section characteristics.
    pub characteristics: u32,
}

impl Section {
    /// Returns the section name as a UTF-8 string when possible.
    #[inline]
    #[must_use]
    pub fn name_str(&self) -> Option<&str> {
        let mut length = 0_usize;
        while length < self.name.len() {
            if self.name.get(length).copied()? == 0 {
                break;
            }
            length = length.saturating_add(1);
        }
        core::str::from_utf8(self.name.get(..length)?).ok()
    }

    /// Returns the maximum of raw and virtual size.
    #[inline]
    #[must_use]
    pub const fn mapped_size(&self) -> u32 {
        if self.virtual_size > self.raw_size {
            self.virtual_size
        } else {
            self.raw_size
        }
    }
}

/// Parsed PE32+ image.
#[derive(Clone, Debug)]
pub struct Pe64<'a> {
    data: &'a [u8],
    lfanew: usize,
    coff_offset: usize,
    optional_offset: usize,
    section_table_offset: usize,
    coff: CoffHeader,
    optional: OptionalHeader,
    sections: Vec<Section>,
}

impl<'a> Pe64<'a> {
    /// Parses and validates a PE32+ AMD64 image.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed headers, unsupported machines or
    /// optional-header magic, section bounds, or alignment violations.
    #[inline]
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x40 {
            return Err(FormatError::Malformed);
        }
        if data.get(0..2) != Some(DOS_MAGIC.as_slice()) {
            return Err(FormatError::Unsupported);
        }
        let lfanew =
            usize::try_from(read_u32(data, DOS_LFANEW_OFFSET)?).map_err(|_| FormatError::Bounds)?;
        let coff_offset = lfanew.checked_add(4).ok_or(FormatError::Bounds)?;
        if data.get(lfanew..lfanew.checked_add(4).ok_or(FormatError::Bounds)?)
            != Some(PE_MAGIC.as_slice())
        {
            return Err(FormatError::Malformed);
        }
        if data.len()
            < coff_offset
                .checked_add(COFF_HEADER_SIZE)
                .ok_or(FormatError::Bounds)?
        {
            return Err(FormatError::Bounds);
        }
        let machine = read_u16(data, coff_offset)?;
        let section_count = read_u16(data, coff_offset.checked_add(2).ok_or(FormatError::Bounds)?)?;
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(FormatError::Unsupported);
        }
        if section_count > MAX_SECTIONS {
            return Err(FormatError::TooManyItems);
        }
        let optimal = CoffHeader {
            machine,
            section_count,
            timestamp: read_u32(data, coff_offset.checked_add(4).ok_or(FormatError::Bounds)?)?,
            symbol_table: read_u32(data, coff_offset.checked_add(8).ok_or(FormatError::Bounds)?)?,
            symbol_count: read_u32(
                data,
                coff_offset.checked_add(12).ok_or(FormatError::Bounds)?,
            )?,
            optional_size: read_u16(
                data,
                coff_offset.checked_add(16).ok_or(FormatError::Bounds)?,
            )?,
            characteristics: read_u16(
                data,
                coff_offset.checked_add(18).ok_or(FormatError::Bounds)?,
            )?,
        };
        if usize::from(optimal.optional_size) < OPTIONAL_FIXED_SIZE {
            return Err(FormatError::Malformed);
        }
        let optional_offset = coff_offset
            .checked_add(COFF_HEADER_SIZE)
            .ok_or(FormatError::Bounds)?;
        if read_u16(data, optional_offset)? != PE32_PLUS_MAGIC {
            return Err(FormatError::Unsupported);
        }
        let section_table_offset = optional_offset
            .checked_add(usize::from(optimal.optional_size))
            .ok_or(FormatError::Bounds)?;
        let section_table_size = usize::from(section_count)
            .checked_mul(SECTION_HEADER_SIZE)
            .ok_or(FormatError::Bounds)?;
        let section_table_end = section_table_offset
            .checked_add(section_table_size)
            .ok_or(FormatError::Bounds)?;
        if section_table_end > data.len() {
            return Err(FormatError::Bounds);
        }
        let optional = OptionalHeader {
            entry_rva: read_u32(
                data,
                optional_offset.checked_add(16).ok_or(FormatError::Bounds)?,
            )?,
            image_base: read_u64(
                data,
                optional_offset.checked_add(24).ok_or(FormatError::Bounds)?,
            )?,
            section_alignment: read_u32(
                data,
                optional_offset.checked_add(32).ok_or(FormatError::Bounds)?,
            )?,
            file_alignment: read_u32(
                data,
                optional_offset.checked_add(36).ok_or(FormatError::Bounds)?,
            )?,
            size_of_image: read_u32(
                data,
                optional_offset.checked_add(56).ok_or(FormatError::Bounds)?,
            )?,
            size_of_headers: read_u32(
                data,
                optional_offset.checked_add(60).ok_or(FormatError::Bounds)?,
            )?,
            checksum: read_u32(
                data,
                optional_offset.checked_add(64).ok_or(FormatError::Bounds)?,
            )?,
            subsystem: read_u16(
                data,
                optional_offset.checked_add(68).ok_or(FormatError::Bounds)?,
            )?,
            dll_characteristics: read_u16(
                data,
                optional_offset.checked_add(70).ok_or(FormatError::Bounds)?,
            )?,
            directory_count: read_u32(
                data,
                optional_offset
                    .checked_add(108)
                    .ok_or(FormatError::Bounds)?,
            )?,
        };
        if optional.section_alignment == 0
            || !optional.section_alignment.is_power_of_two()
            || optional.file_alignment < 512
            || !optional.file_alignment.is_power_of_two()
        {
            return Err(FormatError::BadAlignment);
        }
        if usize::try_from(optional.size_of_headers).unwrap_or(usize::MAX) > data.len() {
            return Err(FormatError::Bounds);
        }
        let mut sections = Vec::with_capacity(usize::from(section_count));
        let mut index = 0_usize;
        while index < usize::from(section_count) {
            let offset = section_table_offset
                .checked_add(
                    index
                        .checked_mul(SECTION_HEADER_SIZE)
                        .ok_or(FormatError::Bounds)?,
                )
                .ok_or(FormatError::Bounds)?;
            let mut name = [0_u8; 8];
            let name_slice = data
                .get(offset..offset.checked_add(8).ok_or(FormatError::Bounds)?)
                .ok_or(FormatError::Bounds)?;
            name.copy_from_slice(name_slice);
            let section = Section {
                name,
                virtual_size: read_u32(data, offset.checked_add(8).ok_or(FormatError::Bounds)?)?,
                virtual_address: read_u32(
                    data,
                    offset.checked_add(12).ok_or(FormatError::Bounds)?,
                )?,
                raw_size: read_u32(data, offset.checked_add(16).ok_or(FormatError::Bounds)?)?,
                raw_offset: read_u32(data, offset.checked_add(20).ok_or(FormatError::Bounds)?)?,
                relocation_offset: read_u32(
                    data,
                    offset.checked_add(24).ok_or(FormatError::Bounds)?,
                )?,
                line_offset: read_u32(data, offset.checked_add(28).ok_or(FormatError::Bounds)?)?,
                relocation_count: read_u16(
                    data,
                    offset.checked_add(32).ok_or(FormatError::Bounds)?,
                )?,
                line_count: read_u16(data, offset.checked_add(34).ok_or(FormatError::Bounds)?)?,
                characteristics: read_u32(
                    data,
                    offset.checked_add(36).ok_or(FormatError::Bounds)?,
                )?,
            };
            if section.raw_size > 0 {
                let start = usize::try_from(section.raw_offset).map_err(|_| FormatError::Bounds)?;
                let size = usize::try_from(section.raw_size).map_err(|_| FormatError::Bounds)?;
                if start.checked_add(size).ok_or(FormatError::Bounds)? > data.len() {
                    return Err(FormatError::Bounds);
                }
            }
            sections.push(section);
            index = index.saturating_add(1);
        }
        Ok(Self {
            data,
            lfanew,
            coff_offset,
            optional_offset,
            section_table_offset,
            coff: optimal,
            optional,
            sections,
        })
    }

    /// Returns the parsed COFF header.
    #[inline]
    #[must_use]
    pub const fn coff_header(&self) -> &CoffHeader {
        &self.coff
    }

    /// Returns the parsed optional header.
    #[inline]
    #[must_use]
    pub const fn optional_header(&self) -> &OptionalHeader {
        &self.optional
    }

    /// Returns all sections.
    #[inline]
    #[must_use]
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Returns the raw input.
    #[inline]
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Maps an RVA range to a file offset.
    #[inline]
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32, size: u32) -> Option<u32> {
        if rva.checked_add(size)? > self.optional.size_of_headers {
            for section in &self.sections {
                let start = section.virtual_address;
                let end = start.checked_add(section.raw_size.max(section.virtual_size))?;
                if rva >= start && rva.checked_add(size)? <= end {
                    let relative = rva.checked_sub(start)?;
                    let offset = section.raw_offset.checked_add(relative)?;
                    if relative.checked_add(size)? <= section.raw_size {
                        return Some(offset);
                    }
                }
            }
            None
        } else {
            Some(rva)
        }
    }

    /// Maps a file offset to an RVA.
    #[inline]
    #[must_use]
    pub fn offset_to_rva(&self, offset: u32) -> Option<u32> {
        for section in &self.sections {
            let start = section.raw_offset;
            let end = start.checked_add(section.raw_size)?;
            if offset >= start && offset < end {
                return section
                    .virtual_address
                    .checked_add(offset.checked_sub(start)?);
            }
        }
        if offset < self.optional.size_of_headers {
            Some(offset)
        } else {
            None
        }
    }

    /// Returns all non-negative-section COFF symbols with inferred sizes.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError`] when the symbol or string table is truncated.
    #[inline]
    pub fn symbols(&self) -> Result<Vec<PeSymbol>> {
        let count = usize::try_from(self.coff.symbol_count).map_err(|_| FormatError::Bounds)?;
        if count == 0 || self.coff.symbol_table == 0 {
            return Ok(Vec::new());
        }
        let table = usize::try_from(self.coff.symbol_table).map_err(|_| FormatError::Bounds)?;
        let string_table = table
            .checked_add(count.checked_mul(18).ok_or(FormatError::Bounds)?)
            .ok_or(FormatError::Bounds)?;
        let string_size =
            usize::try_from(read_u32(self.data, string_table)?).map_err(|_| FormatError::Bounds)?;
        let mut symbols = Vec::new();
        let mut index = 0_usize;
        while index < count {
            let entry = table
                .checked_add(index.checked_mul(18).ok_or(FormatError::Bounds)?)
                .ok_or(FormatError::Bounds)?;
            let name = self.symbol_name(entry, string_table, string_size)?;
            let value = read_u32(self.data, entry.checked_add(8).ok_or(FormatError::Bounds)?)?;
            let section = read_u16(self.data, entry.checked_add(12).ok_or(FormatError::Bounds)?)?;
            let kind = read_u16(self.data, entry.checked_add(14).ok_or(FormatError::Bounds)?)?;
            let storage_class = self
                .data
                .get(entry.checked_add(16).ok_or(FormatError::Bounds)?)
                .copied()
                .ok_or(FormatError::Bounds)?;
            let aux = usize::from(
                self.data
                    .get(entry.checked_add(17).ok_or(FormatError::Bounds)?)
                    .copied()
                    .ok_or(FormatError::Bounds)?,
            );
            if section > 0 && section <= u16::try_from(self.sections.len()).unwrap_or(0) {
                let section_index = usize::from(section.saturating_sub(1));
                if let Some(header) = self.sections.get(section_index) {
                    let rva = header
                        .virtual_address
                        .checked_add(value)
                        .ok_or(FormatError::Bounds)?;
                    symbols.push(PeSymbol {
                        name,
                        rva,
                        size: 0,
                        section,
                        kind,
                        storage_class,
                    });
                }
            }
            index = index
                .checked_add(1)
                .and_then(|next| next.checked_add(aux))
                .ok_or(FormatError::Bounds)?;
        }
        symbols.sort_unstable_by_key(|symbol| (symbol.section, symbol.rva));
        let mut position = 0_usize;
        while position < symbols.len() {
            let Some(symbol) = symbols.get(position) else {
                break;
            };
            let (section, rva) = (symbol.section, symbol.rva);
            let mut cursor = position.saturating_add(1);
            let mut next_rva = None;
            while let Some(next) = symbols.get(cursor) {
                if next.section != section {
                    break;
                }
                if next.rva > rva {
                    next_rva = Some(next.rva);
                    break;
                }
                cursor = cursor.saturating_add(1);
            }
            let end = next_rva.unwrap_or_else(|| {
                self.sections
                    .get(usize::from(section.saturating_sub(1)))
                    .and_then(|header| header.virtual_address.checked_add(header.virtual_size))
                    .unwrap_or(u32::MAX)
            });
            if let Some(symbol) = symbols.get_mut(position) {
                symbol.size = end.saturating_sub(rva);
            }
            position = position.saturating_add(1);
        }
        symbols.sort_unstable_by_key(|symbol| symbol.rva);
        Ok(symbols)
    }

    fn symbol_name(&self, entry: usize, string_table: usize, string_size: usize) -> Result<String> {
        let first = read_u32(self.data, entry)?;
        if first == 0 {
            let offset = usize::try_from(read_u32(
                self.data,
                entry.checked_add(4).ok_or(FormatError::Bounds)?,
            )?)
            .map_err(|_| FormatError::Bounds)?;
            if offset < 4 || offset >= string_size {
                return Err(FormatError::Malformed);
            }
            let start = string_table
                .checked_add(offset)
                .ok_or(FormatError::Bounds)?;
            let end = string_table
                .checked_add(string_size)
                .ok_or(FormatError::Bounds)?;
            let raw = self.data.get(start..end).ok_or(FormatError::Bounds)?;
            let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
            let text = raw.get(..length).ok_or(FormatError::Bounds)?;
            return String::from_utf8(text.to_vec()).map_err(|_| FormatError::Malformed);
        }
        let raw = self
            .data
            .get(entry..entry.checked_add(8).ok_or(FormatError::Bounds)?)
            .ok_or(FormatError::Bounds)?;
        let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        let text = raw.get(..length).ok_or(FormatError::Bounds)?;
        Ok(String::from_utf8_lossy(text).into_owned())
    }

    /// Finds exactly one function symbol by name.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError`] when the symbol is absent or ambiguous.
    #[inline]
    pub fn find_function(&self, name: &str) -> Result<PeSymbol> {
        let matches = self.find_functions_containing(name)?;
        let mut exact = matches.into_iter().filter(|symbol| symbol.name == name);
        let Some(first) = exact.next() else {
            return Err(FormatError::NotFound);
        };
        if exact.next().is_some() {
            return Err(FormatError::Ambiguous);
        }
        Ok(first)
    }

    /// Finds function symbols whose names contain `needle`.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError`] if the symbol table is malformed.
    #[inline]
    pub fn find_functions_containing(&self, needle: &str) -> Result<Vec<PeSymbol>> {
        let mut matches = Vec::new();
        for symbol in self.symbols()? {
            if symbol.kind & 0x20 != 0 && symbol.name.contains(needle) {
                matches.push(symbol);
            }
        }
        Ok(matches)
    }

    /// Returns the section containing an RVA range.
    #[inline]
    #[must_use]
    pub fn section_for_rva(&self, rva: u32, size: u32) -> Option<Section> {
        let end = rva.checked_add(size)?;
        for section in &self.sections {
            let section_end = section.virtual_address.checked_add(section.virtual_size)?;
            if rva >= section.virtual_address && end <= section_end {
                return Some(*section);
            }
        }
        None
    }

    /// Reads bytes at an RVA.
    #[inline]
    #[must_use]
    pub fn read_rva(&self, rva: u32, size: u32) -> Option<&'a [u8]> {
        let offset = self.rva_to_offset(rva, size)?;
        let start = usize::try_from(offset).ok()?;
        let length = usize::try_from(size).ok()?;
        self.data.get(start..start.checked_add(length)?)
    }

    /// Reads one optional-header data directory.
    #[inline]
    #[must_use]
    pub fn data_directory(&self, index: u32) -> Option<(u32, u32)> {
        if index >= self.optional.directory_count {
            return None;
        }
        let relative = usize::try_from(index).ok()?.checked_mul(8)?;
        let offset = self
            .optional_offset
            .checked_add(OPTIONAL_FIXED_SIZE)?
            .checked_add(relative)?;
        let optional_end = self
            .optional_offset
            .checked_add(usize::from(self.coff.optional_size))?;
        if offset.checked_add(8)? > optional_end {
            return None;
        }
        let virtual_address = read_u32(self.data, offset).ok()?;
        let size = read_u32(self.data, offset.checked_add(4)?).ok()?;
        Some((virtual_address, size))
    }

    /// Returns the RVA that [`append_executable_section`] will assign.
    #[inline]
    #[must_use]
    pub fn next_section_rva(&self) -> Option<u32> {
        let aligned = align_up(
            u64::from(self.max_rva_end()),
            u64::from(self.optional.section_alignment),
        )
        .ok()?;
        u32::try_from(aligned).ok()
    }

    /// Finds a section by name.
    #[inline]
    #[must_use]
    pub fn find_section(&self, name: &str) -> Option<(usize, Section)> {
        for (index, section) in self.sections.iter().enumerate() {
            if section.name_str() == Some(name) {
                return Some((index, *section));
            }
        }
        None
    }

    /// Returns the highest mapped RVA end.
    #[inline]
    #[must_use]
    pub fn max_rva_end(&self) -> u32 {
        let mut end = self.optional.size_of_headers;
        for section in &self.sections {
            let candidate = section
                .virtual_address
                .saturating_add(section.mapped_size());
            if candidate > end {
                end = candidate;
            }
        }
        end
    }

    /// Finds exactly one byte pattern in the file.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for no match, `Ambiguous` for multiple matches, and
    /// `Malformed` for an empty pattern.
    #[inline]
    pub fn find_pattern_unique(&self, pattern: &[u8]) -> Result<usize> {
        if pattern.is_empty() {
            return Err(FormatError::Malformed);
        }
        let mut found: Option<usize> = None;
        let mut index = 0_usize;
        while index < self.data.len() {
            if self.data.get(index..index.saturating_add(pattern.len())) == Some(pattern) {
                if found.is_some() {
                    return Err(FormatError::Ambiguous);
                }
                found = Some(index);
            }
            index = index.saturating_add(1);
        }
        found.ok_or(FormatError::NotFound)
    }

    /// Returns the header slack end available for new section headers.
    #[inline]
    #[must_use]
    pub fn section_table_end(&self) -> usize {
        self.section_table_offset.saturating_add(
            usize::from(self.coff.section_count).saturating_mul(SECTION_HEADER_SIZE),
        )
    }

    /// Returns the base of the section table.
    #[inline]
    #[must_use]
    pub const fn section_table_offset(&self) -> usize {
        self.section_table_offset
    }

    /// Returns the PE header offset.
    #[inline]
    #[must_use]
    pub const fn lfanew(&self) -> usize {
        self.lfanew
    }

    /// Returns the COFF header offset.
    #[inline]
    #[must_use]
    pub const fn coff_offset(&self) -> usize {
        self.coff_offset
    }

    /// Returns the optional header offset.
    #[inline]
    #[must_use]
    pub const fn optional_offset(&self) -> usize {
        self.optional_offset
    }
}

/// Result of appending an executable section.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionInjection {
    /// Complete modified image.
    pub image: Vec<u8>,
    /// RVA of the new section.
    pub section_rva: u32,
    /// Raw file offset of the new section.
    pub section_offset: u32,
    /// Raw file size of the new section.
    pub raw_size: u32,
    /// New size of image.
    pub size_of_image: u32,
    /// New section index.
    pub section_index: u16,
}

/// Appends one executable `.sirus` section to a PE32+ image.
///
/// The operation is append-only and requires existing header slack for one
/// section header. It fails closed if the header table has no room.
///
/// # Errors
///
/// Returns a typed error for malformed input, absent header slack, overflow, or
/// an already protected image.
#[inline]
pub fn append_executable_section(original: &[u8], bytes: &[u8]) -> Result<SectionInjection> {
    let pe = Pe64::parse(original)?;
    if pe.find_section(".sirus").is_some() {
        return Err(FormatError::AlreadyProtected);
    }
    if bytes.is_empty() {
        return Err(FormatError::Malformed);
    }
    let new_section_index = pe
        .coff
        .section_count
        .checked_add(1)
        .ok_or(FormatError::TooManyItems)?;
    if new_section_index > MAX_SECTIONS {
        return Err(FormatError::TooManyItems);
    }
    let new_header_offset = pe.section_table_end();
    let new_header_end = new_header_offset
        .checked_add(SECTION_HEADER_SIZE)
        .ok_or(FormatError::Bounds)?;
    let first_raw = pe
        .sections
        .iter()
        .map(|section| section.raw_offset)
        .filter(|offset| *offset > 0)
        .min()
        .unwrap_or(pe.optional.size_of_headers);
    if new_header_end > usize::try_from(pe.optional.size_of_headers).unwrap_or(usize::MAX)
        || new_header_end > usize::try_from(first_raw).unwrap_or(usize::MAX)
    {
        return Err(FormatError::UnsupportedAction);
    }

    let section_alignment = pe.optional.section_alignment;
    let file_alignment = pe.optional.file_alignment;
    let section_rva = align_up(u64::from(pe.max_rva_end()), u64::from(section_alignment))
        .map_err(|_| FormatError::Bounds)?;
    let section_rva = u32::try_from(section_rva).map_err(|_| FormatError::Bounds)?;
    let max_file_end = pe
        .sections
        .iter()
        .map(|section| u64::from(section.raw_offset).saturating_add(u64::from(section.raw_size)))
        .max()
        .unwrap_or_else(|| u64::from(pe.optional.size_of_headers))
        .max(u64::from(pe.optional.size_of_headers))
        .max(u64::try_from(original.len()).unwrap_or(u64::MAX));
    let section_offset = align_up_usize(
        usize::try_from(max_file_end).map_err(|_| FormatError::Bounds)?,
        usize::try_from(file_alignment).map_err(|_| FormatError::Bounds)?,
    )?;
    let raw_size = align_up_usize(
        bytes.len(),
        usize::try_from(file_alignment).map_err(|_| FormatError::Bounds)?,
    )?;
    let raw_size_u32 = u32::try_from(raw_size).map_err(|_| FormatError::Bounds)?;
    let size_of_image = u32::try_from(
        align_up(
            u64::from(section_rva)
                .checked_add(u64::try_from(bytes.len()).map_err(|_| FormatError::Bounds)?)
                .ok_or(FormatError::Bounds)?,
            u64::from(section_alignment),
        )
        .map_err(|_| FormatError::Bounds)?,
    )
    .map_err(|_| FormatError::Bounds)?;

    let mut image = Vec::with_capacity(
        section_offset
            .checked_add(raw_size)
            .ok_or(FormatError::Bounds)?,
    );
    image.extend_from_slice(original);
    image.resize(section_offset, 0);
    image.extend_from_slice(bytes);
    image.resize(section_offset.saturating_add(raw_size), 0);

    let header = image
        .get_mut(new_header_offset..new_header_end)
        .ok_or(FormatError::Bounds)?;
    header.fill(0);
    header
        .get_mut(0..8)
        .ok_or(FormatError::Bounds)?
        .copy_from_slice(b".sirus\0\0");
    write_u32(
        header,
        8,
        u32::try_from(bytes.len()).map_err(|_| FormatError::Bounds)?,
    )?;
    write_u32(header, 12, section_rva)?;
    write_u32(header, 16, raw_size_u32)?;
    write_u32(
        header,
        20,
        u32::try_from(section_offset).map_err(|_| FormatError::Bounds)?,
    )?;
    write_u32(
        header,
        36,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    )?;

    write_u16(
        &mut image,
        pe.coff_offset.checked_add(2).ok_or(FormatError::Bounds)?,
        new_section_index,
    )?;
    write_u32(
        &mut image,
        pe.optional_offset
            .checked_add(56)
            .ok_or(FormatError::Bounds)?,
        size_of_image,
    )?;
    let checksum = pe_checksum(&image, pe.optional_offset)?;
    write_u32(
        &mut image,
        pe.optional_offset
            .checked_add(64)
            .ok_or(FormatError::Bounds)?,
        checksum,
    )?;

    let reparsed = Pe64::parse(&image)?;
    if reparsed.find_section(".sirus").is_none() {
        return Err(FormatError::Malformed);
    }
    Ok(SectionInjection {
        image,
        section_rva,
        section_offset: u32::try_from(section_offset).map_err(|_| FormatError::Bounds)?,
        raw_size: raw_size_u32,
        size_of_image,
        section_index: new_section_index,
    })
}

/// Computes the PE checksum over the complete image.
fn pe_checksum(image: &[u8], checksum_offset: usize) -> Result<u32> {
    let mut sum = 0_u64;
    let mut index = 0_usize;
    while index < image.len() {
        let low = image.get(index).copied().unwrap_or(0);
        let high = image.get(index.saturating_add(1)).copied().unwrap_or(0);
        let word = if index == checksum_offset || index == checksum_offset.saturating_add(2) {
            0
        } else {
            u64::from(low) | (u64::from(high) << 8)
        };
        sum = sum.wrapping_add(word);
        while sum > 0xffff {
            sum = (sum & 0xffff).wrapping_add(sum >> 16);
        }
        index = index.saturating_add(2);
    }
    let folded = u32::try_from(sum & 0xffff).map_err(|_| FormatError::Bounds)?;
    let result = folded.wrapping_add(u32::try_from(image.len()).unwrap_or(u32::MAX));
    Ok(result)
}

/// One new x64 unwind function to merge into the exception directory.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindFunction {
    /// Function start relative to the new section.
    pub begin: u32,
    /// Function end relative to the new section.
    pub end: u32,
    /// Version-1 `UNWIND_INFO` bytes without handler or chained records.
    pub unwind: Vec<u8>,
}

impl UnwindFunction {
    /// Creates a new unwind function record.
    #[inline]
    #[must_use]
    pub const fn new(begin: u32, end: u32, unwind: Vec<u8>) -> Self {
        Self { begin, end, unwind }
    }
}

/// Merges new runtime functions into a section blob and returns the new
/// exception-directory location.
///
/// Existing entries are copied unchanged. New `UNWIND_INFO` records are
/// appended after the table and rebased to `section_rva`. Entries with
/// exception handlers or chained info are rejected because those records
/// contain image-relative pointers this append-only path does not rebase.
///
/// # Errors
///
/// Returns a typed error for malformed tables, overlapping ranges, unsupported
/// unwind records, or arithmetic overflow.
#[inline]
pub fn append_exception_table(
    blob: &mut Vec<u8>,
    pe: &Pe64<'_>,
    section_rva: u32,
    functions: &[UnwindFunction],
) -> Result<Option<(u32, u32)>> {
    if functions.is_empty() {
        return Ok(None);
    }
    let existing = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        Some((0, 0)) | None => Vec::new(),
        Some((0, _)) => return Err(FormatError::Malformed),
        Some((rva, size)) => {
            let entry_size =
                u32::try_from(RUNTIME_FUNCTION_SIZE).map_err(|_| FormatError::Bounds)?;
            if size == 0 || size % entry_size != 0 {
                return Err(FormatError::Malformed);
            }
            pe.read_rva(rva, size).ok_or(FormatError::Bounds)?.to_vec()
        }
    };
    let existing_count = existing.len() / RUNTIME_FUNCTION_SIZE;
    let total_count = existing_count
        .checked_add(functions.len())
        .ok_or(FormatError::TooManyItems)?;
    let pdata_len = total_count
        .checked_mul(RUNTIME_FUNCTION_SIZE)
        .ok_or(FormatError::TooManyItems)?;
    let pdata_offset = align_up_usize(blob.len(), 4)?;
    let xdata_offset = align_up_usize(
        pdata_offset
            .checked_add(pdata_len)
            .ok_or(FormatError::Bounds)?,
        16,
    )?;
    let xdata_rva = section_rva
        .checked_add(u32::try_from(xdata_offset).map_err(|_| FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;

    let mut entries = Vec::with_capacity(total_count);
    let mut offset = 0_usize;
    while offset < existing.len() {
        let begin = read_u32(&existing, offset)?;
        let end = read_u32(&existing, offset.checked_add(4).ok_or(FormatError::Bounds)?)?;
        let unwind = read_u32(&existing, offset.checked_add(8).ok_or(FormatError::Bounds)?)?;
        if begin >= end {
            return Err(FormatError::Malformed);
        }
        entries.push((begin, end, unwind));
        offset = offset
            .checked_add(RUNTIME_FUNCTION_SIZE)
            .ok_or(FormatError::Bounds)?;
    }

    let mut xdata = Vec::new();
    for function in functions {
        if function.begin >= function.end {
            return Err(FormatError::Malformed);
        }
        if function.unwind.len() < 4 {
            return Err(FormatError::Malformed);
        }
        let header = function
            .unwind
            .first()
            .copied()
            .ok_or(FormatError::Malformed)?;
        if header & 0x07 != 1 || header >> 3 != 0 {
            return Err(FormatError::UnsupportedAction);
        }
        let count = usize::from(
            function
                .unwind
                .get(2)
                .copied()
                .ok_or(FormatError::Malformed)?,
        );
        let expected = align_up_usize(
            4_usize
                .checked_add(count.checked_mul(2).ok_or(FormatError::Bounds)?)
                .ok_or(FormatError::Bounds)?,
            4,
        )?;
        if function.unwind.len() < expected {
            return Err(FormatError::Malformed);
        }
        let info_offset = align_up_usize(xdata.len(), 4)?;
        xdata.resize(info_offset, 0);
        xdata.extend_from_slice(
            function
                .unwind
                .get(..expected)
                .ok_or(FormatError::Malformed)?,
        );
        let begin = section_rva
            .checked_add(function.begin)
            .ok_or(FormatError::Bounds)?;
        let end = section_rva
            .checked_add(function.end)
            .ok_or(FormatError::Bounds)?;
        let unwind = xdata_rva
            .checked_add(u32::try_from(info_offset).map_err(|_| FormatError::Bounds)?)
            .ok_or(FormatError::Bounds)?;
        entries.push((begin, end, unwind));
    }
    entries.sort_unstable_by_key(|entry| entry.0);
    let mut index = 1_usize;
    while index < entries.len() {
        let previous = entries
            .get(index.saturating_sub(1))
            .copied()
            .ok_or(FormatError::Malformed)?;
        let current = entries.get(index).copied().ok_or(FormatError::Malformed)?;
        if previous.1 > current.0 {
            return Err(FormatError::Overlap);
        }
        index = index.saturating_add(1);
    }

    let mut pdata = Vec::with_capacity(pdata_len);
    for (begin, end, unwind) in entries {
        let begin_bytes = begin.to_le_bytes();
        let end_bytes = end.to_le_bytes();
        let unwind_bytes = unwind.to_le_bytes();
        pdata.extend_from_slice(&begin_bytes);
        pdata.extend_from_slice(&end_bytes);
        pdata.extend_from_slice(&unwind_bytes);
    }
    blob.resize(pdata_offset, 0);
    blob.extend_from_slice(&pdata);
    blob.resize(xdata_offset, 0);
    blob.extend_from_slice(&xdata);
    Ok(Some((
        section_rva
            .checked_add(u32::try_from(pdata_offset).map_err(|_| FormatError::Bounds)?)
            .ok_or(FormatError::Bounds)?,
        u32::try_from(pdata_len).map_err(|_| FormatError::Bounds)?,
    )))
}

/// Writes one optional-header data directory.
///
/// # Errors
///
/// Returns a typed error when the directory index is out of range or the
/// optional header is truncated.
#[inline]
pub fn write_data_directory(
    image: &mut [u8],
    pe: &Pe64<'_>,
    index: u32,
    virtual_address: u32,
    size: u32,
) -> Result<()> {
    if index >= pe.optional.directory_count {
        return Err(FormatError::UnsupportedAction);
    }
    let relative = usize::try_from(index)
        .map_err(|_| FormatError::Bounds)?
        .checked_mul(8)
        .ok_or(FormatError::Bounds)?;
    let offset = pe
        .optional_offset
        .checked_add(OPTIONAL_FIXED_SIZE)
        .and_then(|value| value.checked_add(relative))
        .ok_or(FormatError::Bounds)?;
    let optional_end = pe
        .optional_offset
        .checked_add(usize::from(pe.coff.optional_size))
        .ok_or(FormatError::Bounds)?;
    if offset.checked_add(8).ok_or(FormatError::Bounds)? > optional_end {
        return Err(FormatError::Bounds);
    }
    write_u32(image, offset, virtual_address)?;
    write_u32(
        image,
        offset.checked_add(4).ok_or(FormatError::Bounds)?,
        size,
    )?;
    Ok(())
}

/// Recomputes and writes the PE checksum.
///
/// # Errors
///
/// Returns a typed error for malformed images or bounds failures.
#[inline]
pub fn refresh_checksum(image: &mut [u8]) -> Result<()> {
    let pe = Pe64::parse(image)?;
    let checksum_offset = pe
        .optional_offset
        .checked_add(64)
        .ok_or(FormatError::Bounds)?;
    let checksum = pe_checksum(image, checksum_offset)?;
    write_u32(image, checksum_offset, checksum)
}

/// Patches a relative jump using RVAs.
///
/// # Errors
///
/// Returns a typed error if the patch location is outside executable raw data,
/// the displacement does not fit, or the image is malformed.
#[inline]
pub fn patch_relative_jump_rva(
    image: &mut [u8],
    from_rva: u32,
    to_rva: u32,
    preserve_endbr: bool,
) -> Result<u32> {
    let pe = Pe64::parse(image)?;
    let mut patch_rva = from_rva;
    if preserve_endbr {
        if let Some(offset) = pe.rva_to_offset(from_rva, 4) {
            let start = usize::try_from(offset).map_err(|_| FormatError::Bounds)?;
            let bytes = image
                .get(start..start.checked_add(4).ok_or(FormatError::Bounds)?)
                .ok_or(FormatError::Bounds)?;
            if bytes == [0xf3, 0x0f, 0x1e, 0xfa] {
                patch_rva = from_rva.checked_add(4).ok_or(FormatError::Bounds)?;
            }
        }
    }
    let next = patch_rva.checked_add(5).ok_or(FormatError::Bounds)?;
    let difference = i128::from(to_rva) - i128::from(next);
    let displacement = i32::try_from(difference).map_err(|_| FormatError::JumpOutOfRange)?;
    let offset = pe.rva_to_offset(patch_rva, 5).ok_or(FormatError::Bounds)?;
    let start = usize::try_from(offset).map_err(|_| FormatError::Bounds)?;
    let target = image
        .get_mut(start..start.checked_add(5).ok_or(FormatError::Bounds)?)
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
    Ok(patch_rva)
}

#[cfg(test)]
mod tests {
    use super::{
        DOS_MAGIC, IMAGE_FILE_MACHINE_AMD64, PE_MAGIC, PE32_PLUS_MAGIC, Pe64, UnwindFunction,
        append_exception_table, append_executable_section, patch_relative_jump_rva, read_u32,
        refresh_checksum, write_data_directory,
    };
    use alloc::vec;
    use alloc::vec::Vec;

    fn synthetic_pe() -> Vec<u8> {
        let mut data = vec![0_u8; 0x800];
        data[0..2].copy_from_slice(&DOS_MAGIC);
        data[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(&PE_MAGIC);
        let coff = 0x84_usize;
        data[coff..coff + 2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());
        let optional = coff + 20;
        data[optional..optional + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        data[optional + 16..optional + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
        data[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        data[optional + 56..optional + 60].copy_from_slice(&0x3000_u32.to_le_bytes());
        data[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        let section_table = optional + 240;
        data[section_table..section_table + 8].copy_from_slice(b".text\0\0\0");
        data[section_table + 8..section_table + 12].copy_from_slice(&0x100_u32.to_le_bytes());
        data[section_table + 12..section_table + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[section_table + 16..section_table + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        data[section_table + 20..section_table + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        data[section_table + 36..section_table + 40].copy_from_slice(
            &(super::IMAGE_SCN_CNT_CODE | super::IMAGE_SCN_MEM_EXECUTE | super::IMAGE_SCN_MEM_READ)
                .to_le_bytes(),
        );
        data[0x200..0x204].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
        data
    }

    #[test]
    fn symbol_table_absent_and_rva_queries_are_total() {
        let data = synthetic_pe();
        let pe = Pe64::parse(&data).expect("pe");
        assert_eq!(pe.symbols().expect("symbols").len(), 0);
        assert_eq!(pe.find_functions_containing("win").expect("find").len(), 0);
        let section = pe.find_section(".text").expect("text");
        assert!(pe.section_for_rva(section.1.virtual_address, 1).is_some());
        assert!(
            pe.section_for_rva(section.1.virtual_address, section.1.virtual_size)
                .is_some()
        );
        assert!(
            pe.section_for_rva(
                section.1.virtual_address,
                section.1.virtual_size.saturating_add(1)
            )
            .is_none()
        );
        assert!(pe.read_rva(section.1.virtual_address, 1).is_some());
        assert!(pe.read_rva(u32::MAX, 1).is_none());
        assert!(pe.find_function("missing").is_err());
        assert_eq!(pe.offset_to_rva(0x100), Some(0x100));
        assert_eq!(pe.offset_to_rva(0x180), Some(0x180));
        assert_eq!(pe.offset_to_rva(0x400), None);
        assert_eq!(pe.rva_to_offset(0x11f0, 0x20), None);
    }

    const SYMBOL_TABLE: usize = 0x400;

    #[allow(
        clippy::too_many_arguments,
        reason = "test helper mirrors the COFF symbol entry layout"
    )]
    fn put_symbol(
        data: &mut [u8],
        index: usize,
        name: &[u8],
        value: u32,
        section: u16,
        kind: u16,
        class: u8,
        aux: u8,
    ) {
        let offset = SYMBOL_TABLE + index * 18;
        data[offset..offset + name.len()].copy_from_slice(name);
        data[offset + 8..offset + 12].copy_from_slice(&value.to_le_bytes());
        data[offset + 12..offset + 14].copy_from_slice(&section.to_le_bytes());
        data[offset + 14..offset + 16].copy_from_slice(&kind.to_le_bytes());
        data[offset + 16] = class;
        data[offset + 17] = aux;
    }

    fn synthetic_pe_with_symbols() -> Vec<u8> {
        let mut data = synthetic_pe();
        let coff = 0x84_usize;
        let count = 6_u32;
        data[coff + 8..coff + 12]
            .copy_from_slice(&u32::try_from(SYMBOL_TABLE).expect("table").to_le_bytes());
        data[coff + 12..coff + 16].copy_from_slice(&count.to_le_bytes());
        put_symbol(&mut data, 0, b"alpha", 0, 1, 0x20, 2, 0);
        put_symbol(&mut data, 1, b"beta", 0x10, 1, 0x20, 2, 1);
        let long = SYMBOL_TABLE + 3 * 18;
        data[long..long + 4].copy_from_slice(&0_u32.to_le_bytes());
        data[long + 4..long + 8].copy_from_slice(&4_u32.to_le_bytes());
        data[long + 8..long + 12].copy_from_slice(&0x30_u32.to_le_bytes());
        data[long + 12..long + 14].copy_from_slice(&1_u16.to_le_bytes());
        data[long + 14..long + 16].copy_from_slice(&0x20_u16.to_le_bytes());
        data[long + 16] = 2;
        put_symbol(&mut data, 4, b"table", 0x40, 1, 0, 3, 0);
        put_symbol(&mut data, 5, b"undef", 0, 0, 0x20, 2, 0);
        let strings = SYMBOL_TABLE + 6 * 18;
        let name = b"a_very_long_function_name";
        data[strings..strings + 4]
            .copy_from_slice(&u32::try_from(name.len() + 5).expect("size").to_le_bytes());
        data[strings + 4..strings + 4 + name.len()].copy_from_slice(name);
        data
    }

    #[test]
    fn parses_coff_symbols_with_sizes_and_long_names() {
        let data = synthetic_pe_with_symbols();
        let pe = Pe64::parse(&data).expect("pe");
        let symbols = pe.symbols().expect("symbols");
        assert_eq!(symbols.len(), 4);
        assert_eq!(
            symbols.first().map(|symbol| symbol.name.as_str()),
            Some("alpha")
        );
        let alpha = pe.find_function("alpha").expect("alpha");
        assert_eq!((alpha.rva, alpha.size), (0x1000, 0x10));
        assert_eq!(alpha.storage_class, 2);
        let beta = pe.find_function("beta").expect("beta");
        assert_eq!((beta.rva, beta.size), (0x1010, 0x20));
        assert_eq!(beta.kind, 0x20);
        let long = pe.find_function("a_very_long_function_name").expect("long");
        assert_eq!((long.rva, long.size), (0x1030, 0x10));
        assert!(pe.find_function("table").is_err());
        let matches = pe.find_functions_containing("very_long").expect("find");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().map(|symbol| symbol.rva), Some(0x1030));

        let mut section_alias = data.clone();
        put_symbol(&mut section_alias, 5, b".text", 0, 1, 0, 3, 0);
        let pe = Pe64::parse(&section_alias).expect("pe");
        let alpha = pe.find_function("alpha").expect("alpha");
        assert_eq!((alpha.rva, alpha.size), (0x1000, 0x10));

        let mut duplicate = data;
        put_symbol(&mut duplicate, 4, b"alpha", 0x40, 1, 0x20, 3, 0);
        let pe = Pe64::parse(&duplicate).expect("pe");
        assert!(matches!(
            pe.find_function("alpha"),
            Err(crate::FormatError::Ambiguous)
        ));
    }

    #[test]
    fn rejects_malformed_symbol_tables() {
        let base = synthetic_pe_with_symbols();
        let coff = 0x84_usize;
        let long = SYMBOL_TABLE + 3 * 18;

        let mut missing = base.clone();
        missing[coff + 8..coff + 12].copy_from_slice(&0x7f0_u32.to_le_bytes());
        assert!(Pe64::parse(&missing).expect("pe").symbols().is_err());

        let mut offset_zero = base.clone();
        offset_zero[long + 4..long + 8].copy_from_slice(&0_u32.to_le_bytes());
        assert!(Pe64::parse(&offset_zero).expect("pe").symbols().is_err());

        let mut offset_past = base.clone();
        offset_past[long + 4..long + 8].copy_from_slice(&0x1000_u32.to_le_bytes());
        assert!(Pe64::parse(&offset_past).expect("pe").symbols().is_err());

        let mut invalid_utf8 = base;
        let strings = SYMBOL_TABLE + 6 * 18;
        invalid_utf8[strings + 4] = 0xff;
        assert!(Pe64::parse(&invalid_utf8).expect("pe").symbols().is_err());
    }

    #[test]
    fn parses_synthetic_pe() {
        let data = synthetic_pe();
        let pe = Pe64::parse(&data).expect("parse");
        assert_eq!(pe.coff_header().machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(pe.sections().len(), 1);
        assert_eq!(pe.optional_header().entry_rva, 0x1000);
        assert_eq!(pe.rva_to_offset(0x1000, 4), Some(0x200));
        assert_eq!(pe.find_section(".text").map(|value| value.0), Some(0));
    }

    #[test]
    fn appends_executable_section() {
        let data = synthetic_pe();
        let bytes = vec![0x90_u8; 0x123];
        let result = append_executable_section(&data, &bytes).expect("append");
        let pe = Pe64::parse(&result.image).expect("reparse");
        assert_eq!(pe.sections().len(), 2);
        assert!(pe.find_section(".sirus").is_some());
        assert_eq!(result.section_rva, 0x2000);
        assert_eq!(result.raw_size, 0x200);
        assert!(result.image.len() >= usize::try_from(result.section_offset).unwrap_or(0) + 0x123);
    }

    #[test]
    fn patches_relative_jump() {
        let data = synthetic_pe();
        let result = append_executable_section(&data, &[0x90; 0x20]).expect("append");
        let mut image = result.image;
        let patch =
            patch_relative_jump_rva(&mut image, 0x1000, result.section_rva, false).expect("patch");
        assert_eq!(patch, 0x1000);
        let pe = Pe64::parse(&image).expect("reparse");
        let offset = pe.rva_to_offset(0x1000, 5).expect("offset");
        let bytes = image
            .get(usize::try_from(offset).unwrap_or(0)..usize::try_from(offset).unwrap_or(0) + 5)
            .expect("bytes");
        assert_eq!(bytes.first(), Some(&0xe9));
    }
    #[test]
    fn rejects_malformed_pe_headers() {
        let base = synthetic_pe();
        let mut cases = Vec::new();
        cases.push(Vec::new());
        let mut wrong_dos = base.clone();
        wrong_dos[0] = 0;
        cases.push(wrong_dos);
        let mut wrong_signature = base.clone();
        wrong_signature[0x80] = 0;
        cases.push(wrong_signature);
        let mut wrong_machine = base.clone();
        wrong_machine[0x84..0x86].copy_from_slice(&3_u16.to_le_bytes());
        cases.push(wrong_machine);
        let mut wrong_magic = base.clone();
        wrong_magic[0x98..0x9a].copy_from_slice(&0x10b_u16.to_le_bytes());
        cases.push(wrong_magic);
        let mut bad_lfanew = base;
        bad_lfanew[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(bad_lfanew);
        for case in cases {
            assert!(Pe64::parse(&case).is_err());
        }
    }

    #[test]
    fn reports_section_and_pattern_queries() {
        let data = synthetic_pe();
        let pe = Pe64::parse(&data).expect("parse");
        assert_eq!(pe.find_section(".text").map(|value| value.0), Some(0));
        assert!(pe.find_section(".sirus").is_none());
        assert_eq!(pe.rva_to_offset(0x1000, 4), Some(0x200));
        assert_eq!(pe.rva_to_offset(0xffff_ffff, 4), None);
        assert_eq!(pe.offset_to_rva(0x200), Some(0x1000));
        assert_eq!(pe.offset_to_rva(0xffff_ffff), None);
        assert!(pe.max_rva_end() >= 0x1000);
        assert_eq!(
            pe.find_pattern_unique(&[]),
            Err(crate::FormatError::Malformed)
        );
        assert_eq!(
            pe.find_pattern_unique(&[0]),
            Err(crate::FormatError::Ambiguous)
        );
        assert_eq!(
            pe.find_pattern_unique(b"not-present-pattern"),
            Err(crate::FormatError::NotFound)
        );
    }

    #[test]
    fn section_injection_errors_are_typed() {
        let data = synthetic_pe();
        assert_eq!(
            append_executable_section(&data, &[]).err(),
            Some(crate::FormatError::Malformed)
        );
        let first = append_executable_section(&data, &[0x90; 0x20]).expect("first");
        assert_eq!(
            append_executable_section(&first.image, &[0x90; 0x20]).err(),
            Some(crate::FormatError::AlreadyProtected)
        );
        let mut image = first.image;
        assert!(patch_relative_jump_rva(&mut image, 0xffff_ffff, 0x1000, false).is_err());
        let mut no_slack = data;
        no_slack[0x98 + 60..0x98 + 64].copy_from_slice(&0x1a8_u32.to_le_bytes());
        assert!(append_executable_section(&no_slack, &[0x90; 0x20]).is_err());
    }
    fn synthetic_pe_with_exception() -> Vec<u8> {
        let mut data = synthetic_pe();
        let optional = 0x98_usize;
        data[optional + 108..optional + 112].copy_from_slice(&4_u32.to_le_bytes());
        data[optional + 112 + 24..optional + 112 + 28].copy_from_slice(&0x1070_u32.to_le_bytes());
        data[optional + 112 + 28..optional + 112 + 32].copy_from_slice(&12_u32.to_le_bytes());
        data[0x260..0x264].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        data[0x270..0x274].copy_from_slice(&0x1040_u32.to_le_bytes());
        data[0x274..0x278].copy_from_slice(&0x1050_u32.to_le_bytes());
        data[0x278..0x27c].copy_from_slice(&0x1060_u32.to_le_bytes());
        data
    }

    fn unwind(count: u8) -> Vec<u8> {
        let size = (4 + usize::from(count) * 2 + 3) & !3;
        let mut bytes = vec![0_u8; size];
        bytes[0] = 1;
        bytes[2] = count;
        bytes
    }

    #[test]
    fn merges_exception_entries_and_rebases_new_unwind_info() {
        let data = synthetic_pe_with_exception();
        let pe = Pe64::parse(&data).expect("pe");
        assert_eq!(pe.data_directory(3), Some((0x1070, 12)));
        assert_eq!(pe.next_section_rva(), Some(0x2000));
        let mut blob = vec![0xaa_u8; 0x20];
        let directory = append_exception_table(
            &mut blob,
            &pe,
            0x2000,
            &[UnwindFunction::new(0x10, 0x20, unwind(1))],
        )
        .expect("merge")
        .expect("directory");
        assert_eq!(directory, (0x2020, 24));
        assert_eq!(read_u32(&blob, 0x20).expect("first begin"), 0x1040);
        assert_eq!(read_u32(&blob, 0x2c).expect("new begin"), 0x2010);
        assert_eq!(read_u32(&blob, 0x30).expect("new end"), 0x2020);
        assert_eq!(read_u32(&blob, 0x34).expect("new unwind"), 0x2040);
        assert_eq!(
            blob.get(0x40..0x48),
            Some([1, 0, 1, 0, 0, 0, 0, 0].as_slice())
        );
        assert_eq!(blob.len(), 0x48);
    }

    #[test]
    fn exception_merge_rejects_overlap_and_handlers() {
        let data = synthetic_pe_with_exception();
        let pe = Pe64::parse(&data).expect("pe");
        let mut blob = Vec::new();
        assert_eq!(
            append_exception_table(
                &mut blob,
                &pe,
                0x2000,
                &[
                    UnwindFunction::new(0x10, 0x20, unwind(0)),
                    UnwindFunction::new(0x18, 0x28, unwind(0)),
                ],
            )
            .err(),
            Some(crate::FormatError::Overlap)
        );
        let mut handler = unwind(0);
        handler[0] = 0x09;
        assert_eq!(
            append_exception_table(
                &mut blob,
                &pe,
                0x2000,
                &[UnwindFunction::new(0x10, 0x20, handler)],
            )
            .err(),
            Some(crate::FormatError::UnsupportedAction)
        );
    }

    #[test]
    fn exception_table_rejects_malformed_entries() {
        let base = synthetic_pe_with_exception();
        let pe = Pe64::parse(&base).expect("pe");
        let mut blob = Vec::new();
        assert_eq!(
            append_exception_table(&mut blob, &pe, 0x2000, &[]).expect("empty"),
            None
        );
        assert_eq!(
            append_exception_table(
                &mut blob,
                &pe,
                0x2000,
                &[UnwindFunction::new(0x10, 0x10, unwind(0))],
            )
            .err(),
            Some(crate::FormatError::Malformed)
        );
        assert_eq!(
            append_exception_table(
                &mut blob,
                &pe,
                0x2000,
                &[UnwindFunction::new(0x10, 0x20, vec![1, 0, 0])],
            )
            .err(),
            Some(crate::FormatError::Malformed)
        );
        let mut short = unwind(1);
        short.truncate(4);
        assert_eq!(
            append_exception_table(
                &mut blob,
                &pe,
                0x2000,
                &[UnwindFunction::new(0x10, 0x20, short)],
            )
            .err(),
            Some(crate::FormatError::Malformed)
        );

        let optional = 0x98_usize;
        let mut bad_size = base.clone();
        bad_size[optional + 112 + 28..optional + 112 + 32].copy_from_slice(&13_u32.to_le_bytes());
        let bad_pe = Pe64::parse(&bad_size).expect("bad size");
        assert_eq!(
            append_exception_table(
                &mut blob,
                &bad_pe,
                0x2000,
                &[UnwindFunction::new(0x10, 0x20, unwind(0))],
            )
            .err(),
            Some(crate::FormatError::Malformed)
        );

        let mut bad_range = base.clone();
        bad_range[0x270..0x274].copy_from_slice(&0x1050_u32.to_le_bytes());
        bad_range[0x274..0x278].copy_from_slice(&0x1040_u32.to_le_bytes());
        let bad_pe = Pe64::parse(&bad_range).expect("bad range");
        assert_eq!(
            append_exception_table(
                &mut blob,
                &bad_pe,
                0x2000,
                &[UnwindFunction::new(0x10, 0x20, unwind(0))],
            )
            .err(),
            Some(crate::FormatError::Malformed)
        );
    }

    #[test]
    fn directory_updates_refresh_the_checksum() {
        let mut image = synthetic_pe_with_exception();
        let source = image.clone();
        let pe = Pe64::parse(&source).expect("pe");
        let before = pe.optional_header().checksum;
        write_data_directory(&mut image, &pe, 3, 0x2020, 24).expect("directory");
        {
            let updated = Pe64::parse(&image).expect("updated");
            assert_eq!(updated.data_directory(3), Some((0x2020, 24)));
        }
        refresh_checksum(&mut image).expect("checksum");
        {
            let refreshed = Pe64::parse(&image).expect("refreshed");
            assert_ne!(refreshed.optional_header().checksum, before);
        }
        let source = image.clone();
        let pe = Pe64::parse(&source).expect("pe");
        assert_eq!(
            write_data_directory(&mut image, &pe, 32, 0, 0).err(),
            Some(crate::FormatError::UnsupportedAction)
        );
    }

    #[test]
    fn malformed_prefixes_and_mutations_fail_closed() {
        let base = synthetic_pe();
        let mut length = 0_usize;
        while length <= base.len() {
            if let Some(prefix) = base.get(..length) {
                drop(Pe64::parse(prefix));
            }
            length = length.saturating_add(5);
        }
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
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
                    *byte ^= u8::try_from((state >> 24) & 0xff).unwrap_or(1);
                }
                flips = flips.saturating_add(1);
            }
            if let Ok(pe) = Pe64::parse(&mutated) {
                let _ = pe.find_section(".text");
                let _ = pe.max_rva_end();
                let _ = pe.section_table_end();
            }
            round = round.saturating_add(1);
        }
    }
}
