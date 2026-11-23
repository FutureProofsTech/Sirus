//! PE32+ / x86-64 parsing and append-only executable-section injection.
//!
//! This backend covers the Windows executable container. Runtime injection is
//! not claimed for Windows yet: the generated VM ABI and linker must be validated
//! on a Windows toolchain. Parsing, section addition, RVA mapping, checksum
//! regeneration, and jump patching are implemented and tested structurally.

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
        DOS_MAGIC, IMAGE_FILE_MACHINE_AMD64, PE_MAGIC, PE32_PLUS_MAGIC, Pe64,
        append_executable_section, patch_relative_jump_rva,
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
}
