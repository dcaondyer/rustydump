use super::{BinaryFormat, ExecutableSection};
use goblin::mach::{Mach, MachO, SingleArch};
use std::error::Error;

pub struct MachoFormat;

impl BinaryFormat for MachoFormat {
    fn format_name() -> &'static str {
        "Mach-O (macOS/iOS)"
    }

    fn parse(bytes: &[u8]) -> Result<Vec<ExecutableSection>, Box<dyn Error>> {
        match Mach::parse(bytes)? {
            Mach::Binary(macho) => parse_macho(&macho, bytes),
            Mach::Fat(fat) => {
                // Fat binary: contiene più architetture (es. x86_64 + arm64)
                let mut all_sections = Vec::new();
                for arch in fat.into_iter() {
                    match arch? {
                        SingleArch::MachO(macho) => {
                            let mut sections = parse_macho(&macho, bytes)?;
                            all_sections.append(&mut sections);
                        }
                        SingleArch::Archive(_) => {
                            eprintln!("Static archive inside fat binary, skip...");
                        }
                    }
                }
                Ok(all_sections)
            }
        }
    }
}

fn parse_macho(macho: &MachO, bytes: &[u8]) -> Result<Vec<ExecutableSection>, Box<dyn Error>> {
    let mut sections = Vec::new();

    for segment in macho.segments.iter() {
        let seg_name = segment.name().unwrap_or("?");

        // Solo i segmenti __TEXT contengono codice eseguibile
        if seg_name != "__TEXT" {
            continue;
        }

        for section in segment.sections()? {
            let (section, _data) = section;
            let sect_name = section.name().unwrap_or("?");

            // Flags: S_ATTR_PURE_INSTRUCTIONS = 0x8000_0000
            //        S_ATTR_SOME_INSTRUCTIONS = 0x0040_0000
            let flags = section.flags;
            let is_executable = flags & 0x8000_0000 != 0 || flags & 0x0040_0000 != 0;

            // Includi sempre __text anche se i flag non sono settati
            let is_text = sect_name == "__text";

            if !is_executable && !is_text {
                continue;
            }

            let offset = section.offset as usize;
            let size = section.size as usize;

            if size == 0 {
                continue;
            }

            if offset + size > bytes.len() {
                eprintln!(
                    "Section '{}/{}' out of bounds (offset: {}, size: {}), skip...",
                    seg_name, sect_name, offset, size
                );
                continue;
            }

            let data = bytes[offset..offset + size].to_vec();
            let virtual_address = section.addr;
            let name = format!("{}/{}", seg_name, sect_name);

            sections.push(ExecutableSection {
                name,
                data,
                virtual_address,
            });
        }
    }

    if sections.is_empty() {
        eprintln!("No executable section found in Mach-O");
    }

    Ok(sections)
}
