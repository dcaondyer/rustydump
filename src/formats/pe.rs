use super::{BinaryFormat, ExecutableSection};
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
            let is_executable = section.characteristics & 0x2000_0000 != 0;
            if !is_executable {
                continue;
            }

            let name = section.name().unwrap_or("?").to_string();

            let offset = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;

            if offset + size > bytes.len() {
                eprintln!("Section '{}' out of bounds, skip...", name);
                continue;
            }

            let data = bytes[offset..offset + size].to_vec();
            let virtual_address = section.virtual_address as u64 + pe.image_base as u64;

            sections.push(ExecutableSection {
                name,
                data,
                virtual_address,
            });
        }

        Ok(sections)
    }
}
