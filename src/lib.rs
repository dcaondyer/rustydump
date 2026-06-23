pub mod config;
pub mod disasm;
pub mod formats;
pub mod output;

use crate::config::InstructionFormat;
use config::Config;
use disasm::disasm;
use formats::{elf::ElfFormat, macho::MachoFormat, pe::PeFormat, BinaryFormat};
use goblin::Object;
use std::error::Error;
use std::fs;

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(&config.file_path)?;

    // Rileva automaticamente il formato con goblin
    match Object::parse(&bytes)? {
        Object::PE(_) => {
            println!("Format found: {}", PeFormat::format_name());
            process_sections::<PeFormat>(
                &bytes,
                config.code_bitness,
                config.code_rip,
                config.instr_format,
            )?;
        }
        Object::Elf(_) => {
            println!("Format found: {}", ElfFormat::format_name());
            process_sections::<ElfFormat>(
                &bytes,
                config.code_bitness,
                config.code_rip,
                config.instr_format,
            )?;
        }
        Object::Mach(_) => {
            // <-- nuovo
            println!("Formato rilevato: {}", MachoFormat::format_name());
            process_sections::<MachoFormat>(
                &bytes,
                config.code_bitness,
                config.code_rip,
                config.instr_format,
            )?;
        }
        Object::Unknown(magic) => {
            eprintln!(
                "Unknown format (magic: 0x{:x}), disassembling raw...",
                magic
            );
            disasm(
                config.code_bitness,
                &bytes,
                config.code_rip,
                &config.instr_format,
            );
        }
        _ => {
            eprintln!("Format not supported, disassembling raw...");
            disasm(
                config.code_bitness,
                &bytes,
                config.code_rip,
                &config.instr_format,
            );
        }
    }

    Ok(())
}

fn process_sections<F: BinaryFormat>(
    bytes: &[u8],
    bitness: u32,
    fallback_rip: u64,
    instr_format: InstructionFormat,
) -> Result<(), Box<dyn Error>> {
    let sections = F::parse(bytes)?;

    if sections.is_empty() {
        eprintln!("No executable sections found");
        return Ok(());
    }

    for section in sections {
        println!();
        println!("══════════════════════════════════════════");
        println!(
            "  Section: {}  (VA: 0x{:x})",
            section.name, section.virtual_address
        );
        println!("══════════════════════════════════════════");
        let rip = if section.virtual_address != 0 {
            section.virtual_address
        } else {
            fallback_rip
        };
        disasm(bitness, &section.data, rip, &instr_format);
    }

    println!();
    println!("Disassembly completed");

    Ok(())
}
