use super::{BinaryFormat, ExecutableSection};
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
            let is_executable = section.sh_flags & 0x4 != 0;
            if !is_executable {
                continue;
            }

            let name = elf
                .shdr_strtab
                .get_at(section.sh_name)
                .unwrap_or("?")
                .to_string();

            let offset = section.sh_offset as usize;
            let size = section.sh_size as usize;

            if size == 0 || offset + size > bytes.len() {
                continue;
            }

            let data = bytes[offset..offset + size].to_vec();
            let virtual_address = section.sh_addr;

            sections.push(ExecutableSection {
                name,
                data,
                virtual_address,
            });
        }

        Ok(sections)
    }
}
