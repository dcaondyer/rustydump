use super::{BinaryFormat, ExecutableFormat, ExecutableSection};
use goblin::pe::PE;
use std::error::Error;

pub struct PeFormat;

impl BinaryFormat for PeFormat {
    fn format_name() -> &'static str {
        "PE (Windows)"
    }

    fn parse(bytes: &[u8]) -> Result<Vec<ExecutableSection>, Box<dyn Error>> {
        let pe = PE::parse(bytes)?;
        let mut sections = Vec::new();

        for section in &pe.sections {
            // Considera solo sezioni eseguibili (flag 0x20000000)
            let section_flags = section.characteristics;
            let is_executable = section_flags & 0x2000_0000 != 0;
            if !is_executable {
                continue;
            }

            let name = section.name().unwrap_or("?").to_string();

            let offset = section.pointer_to_raw_data as u64;
            let size = section.size_of_raw_data as u64;

            let offset_usize = offset as usize;
            let size_usize = size as usize;

            if offset_usize + size_usize > bytes.len() {
                eprintln!("Section '{}' out of bounds, skip...", name);
                continue;
            }

            let data = bytes[offset_usize..offset_usize + size_usize].to_vec();
            let virtual_address = section.virtual_address as u64 + pe.image_base as u64;

            let section_flags = if section_flags != 0 {
                Some(section_flags as u64)
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
                object_format: Some(ExecutableFormat::PE),
            });
        }

        Ok(sections)
    }
}
