use super::{BinaryFormat, ExecutableFormat, ExecutableSection};
use goblin::elf::Elf;
use std::error::Error;

pub struct ElfFormat;

impl BinaryFormat for ElfFormat {
    fn format_name() -> &'static str {
        "ELF (Linux/Unix)"
    }

    fn parse(bytes: &[u8]) -> Result<Vec<ExecutableSection>, Box<dyn Error>> {
        let elf = Elf::parse(bytes)?;
        let mut sections = Vec::new();

        for section in &elf.section_headers {
            // SHF_EXECINSTR = 0x4 → sezione con istruzioni
            let section_flags = section.sh_flags;
            let is_executable = section_flags & 0x4 != 0;
            if !is_executable {
                continue;
            }

            let name = elf
                .shdr_strtab
                .get_at(section.sh_name)
                .unwrap_or("?")
                .to_string();

            let offset = section.sh_offset;
            let size = section.sh_size;

            let offset_usize = offset as usize;
            let size_usize = size as usize;

            if size_usize == 0 || offset_usize + size_usize > bytes.len() {
                continue;
            }

            let data = bytes[offset_usize..offset_usize + size_usize].to_vec();
            let virtual_address = section.sh_addr;

            let section_flags = if section_flags != 0 {
                Some(section_flags)
            } else {
                None
            };

            sections.push(ExecutableSection {
                name,
                data,
                virtual_address,
                offset,
                size,
                section_flags,
                object_format: Some(ExecutableFormat::Elf),
            });
        }

        Ok(sections)
    }
}
