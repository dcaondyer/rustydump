pub mod config;
pub mod disasm;
pub mod formats;
pub mod output;

use crate::config::Config;
use crate::disasm::disasm;
use crate::formats::{
    elf::ElfFormat, macho::MachoFormat, pe::PeFormat, BinaryFormat, ExecutableSection,
};
use goblin::Object;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

pub fn process_file(file: &PathBuf, config: &Config) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(file)?;

    // Header del file come objdump: "file.bin:     file format elf64-x86-64"
    let format_name = detect_format_name(&bytes);
    println!("\n{}:     file format {}", file.display(), format_name);

    // Esegui le azioni richieste in ordine (come objdump)
    if config.file_headers || config.all_headers {
        print_file_headers(&bytes, file)?;
    }
    if config.section_headers || config.all_headers {
        print_section_headers(&bytes)?;
    }
    if config.private_headers || config.all_headers {
        print_private_headers(&bytes)?;
    }
    if config.syms || config.all_headers {
        print_symbol_table(&bytes)?;
    }
    if config.dynamic_syms {
        print_dynamic_syms(&bytes)?;
    }
    if config.full_contents {
        print_full_contents(&bytes, config.section_filter.as_deref())?;
    }
    if config.disassemble || config.disassemble_all {
        disassemble(&bytes, config)?;
    }

    Ok(())
}

// ── Rilevamento formato ───────────────────────────────────────────────────

fn detect_format_name(bytes: &[u8]) -> &'static str {
    match Object::parse(bytes) {
        Ok(Object::Elf(elf)) => {
            if elf.is_64 {
                "elf64-x86-64"
            } else {
                "elf32-i386"
            }
        }
        Ok(Object::PE(pe)) => {
            if pe.is_64 {
                "pe-x86-64"
            } else {
                "pe-i386"
            }
        }
        Ok(Object::Mach(_)) => "mach-o",
        _ => "unknown",
    }
}

// ── -f / --file-headers ───────────────────────────────────────────────────

fn print_file_headers(bytes: &[u8], file: &PathBuf) -> Result<(), Box<dyn Error>> {
    println!();
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            let arch = if elf.is_64 { "i386:x86-64" } else { "i386" };
            println!("{}", file.display());
            println!("architecture: {arch}, flags 0x{:08x}:", 0u32);
            println!("start address 0x{:016x}", elf.entry);
        }
        Object::PE(pe) => {
            let arch = if pe.is_64 { "i386:x86-64" } else { "i386" };
            println!("architecture: {arch}");
            println!(
                "start address 0x{:016x}",
                pe.entry as u64 + pe.image_base as u64
            );
        }
        Object::Mach(mach) => {
            println!("architecture: mach-o");
            use goblin::mach::Mach;
            if let Mach::Binary(m) = mach {
                println!("start address 0x{:016x}", m.entry);
            }
        }
        _ => println!("(header not present)"),
    }
    Ok(())
}

// ── -h / --section-headers ────────────────────────────────────────────────

fn print_section_headers(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    println!();
    println!("Sections:");
    // Header colonne identico a objdump
    println!(
        "{:<4} {:<20} {:>8} {:>16} {:>16} {:>8} {:>4}  {}",
        "Idx", "Name", "Size", "VMA", "LMA", "File off", "Algn", "Flags"
    );

    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            for (idx, section) in elf.section_headers.iter().enumerate() {
                let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("?");
                println!(
                    "{:<4} {:<20} {:>8x} {:>16x} {:>16x} {:>8x} 2**{}  {:?}",
                    idx,
                    name,
                    section.sh_size,
                    section.sh_addr,
                    section.sh_addr,
                    section.sh_offset,
                    section.sh_addralign.trailing_zeros(),
                    section_flags_elf(section.sh_flags),
                );
            }
        }
        Object::PE(pe) => {
            for (idx, section) in pe.sections.iter().enumerate() {
                let name = section.name().unwrap_or("?");
                let vma = section.virtual_address as u64 + pe.image_base as u64;
                println!(
                    "{:<4} {:<20} {:>8x} {:>16x} {:>16x} {:>8x} 2**4  {}",
                    idx,
                    name,
                    section.size_of_raw_data,
                    vma,
                    vma,
                    section.pointer_to_raw_data,
                    section_flags_pe(section.characteristics),
                );
            }
        }
        Object::Mach(mach) => {
            use goblin::mach::Mach;
            if let Mach::Binary(m) = mach {
                let mut idx = 0;
                for seg in m.segments.iter() {
                    for section in seg.sections()? {
                        let (s, _) = section;
                        let name =
                            format!("{}/{}", seg.name().unwrap_or("?"), s.name().unwrap_or("?"));
                        println!(
                            "{:<4} {:<20} {:>8x} {:>16x} {:>16x} {:>8x} 2**{}",
                            idx, name, s.size, s.addr, s.addr, s.offset, s.align,
                        );
                        idx += 1;
                    }
                }
            }
        }
        _ => println!("(sections not present)"),
    }
    Ok(())
}

// ── -p / --private-headers ────────────────────────────────────────────────

fn print_private_headers(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    println!();
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            println!("Program Header:");
            for ph in &elf.program_headers {
                println!(
                    "  {:?}  off 0x{:016x} vaddr 0x{:016x} paddr 0x{:016x}",
                    ph.p_type, ph.p_offset, ph.p_vaddr, ph.p_paddr
                );
                println!(
                    "       filesz 0x{:016x} memsz 0x{:016x} flags {:?} align 2**{}",
                    ph.p_filesz,
                    ph.p_memsz,
                    ph.p_flags,
                    ph.p_align.trailing_zeros()
                );
            }
        }
        Object::PE(pe) => {
            println!(
                "PE information: 0x{:04x}",
                pe.header.coff_header.characteristics
            );
            if let Some(opt) = pe.header.optional_header {
                println!(
                    "Image base:        0x{:016x}",
                    opt.windows_fields.image_base
                );
                println!(
                    "Section alignment: 0x{:x}",
                    opt.windows_fields.section_alignment
                );
                println!(
                    "File alignment:    0x{:x}",
                    opt.windows_fields.file_alignment
                );
                println!(
                    "Stack reserve:     0x{:x}",
                    opt.windows_fields.size_of_stack_reserve
                );
                println!(
                    "Heap reserve:      0x{:x}",
                    opt.windows_fields.size_of_heap_reserve
                );
            }
        }
        Object::Mach(mach) => {
            use goblin::mach::Mach;
            if let Mach::Binary(m) = mach {
                println!("Load commands: {}", m.load_commands.len());
                for lc in &m.load_commands {
                    println!("  {:?}", lc.command);
                }
            }
        }
        _ => println!("(private headers not present)"),
    }
    Ok(())
}

// ── -t / --syms ───────────────────────────────────────────────────────────

fn print_symbol_table(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    println!();
    println!("SYMBOL TABLE:");
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            for sym in elf.syms.iter() {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("?");
                let bind = if sym.st_bind() == 1 { "g" } else { "l" };
                let kind = match sym.st_type() {
                    1 => "O",
                    2 => "F",
                    3 => "f",
                    _ => " ",
                };
                println!(
                    "{:016x} {} {} {:016x} {}",
                    sym.st_value, bind, kind, sym.st_size, name
                );
            }
        }
        Object::PE(pe) => {
            for sym in &pe.exports {
                println!(
                    "{:016x} g F {:016x} {}",
                    sym.rva as u64 + pe.image_base as u64,
                    0u64,
                    sym.name.unwrap_or("?")
                );
            }
        }
        Object::Mach(mach) => {
            use goblin::mach::Mach;
            if let Mach::Binary(m) = mach {
                for sym in m.symbols().flatten() {
                    let (name, nlist) = sym;
                    println!("{:016x}   {:016x} {}", nlist.n_value, 0u64, name);
                }
            }
        }
        _ => println!("(symbol table not present)"),
    }
    Ok(())
}

// ── -T / --dynamic-syms ───────────────────────────────────────────────────

fn print_dynamic_syms(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    println!();
    println!("DYNAMIC SYMBOL TABLE:");
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            for sym in elf.dynsyms.iter() {
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("?");
                let bind = if sym.st_bind() == 1 { "g" } else { "l" };
                println!(
                    "{:016x} {} F {:016x} {}",
                    sym.st_value, bind, sym.st_size, name
                );
            }
        }
        Object::PE(pe) => {
            for import in &pe.imports {
                println!(
                    "{:016x} g F 0000000000000000 {}",
                    import.rva as u64, import.name
                );
            }
        }
        _ => println!("(dynamic symbol table not present)"),
    }
    Ok(())
}

// ── -s / --full-contents ──────────────────────────────────────────────────

fn print_full_contents(bytes: &[u8], filter: Option<&str>) -> Result<(), Box<dyn Error>> {
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            for section in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("?");
                if filter.map_or(false, |f| f != name) {
                    continue;
                }
                let off = section.sh_offset as usize;
                let size = section.sh_size as usize;
                if size == 0 {
                    continue;
                }
                print_hex_dump(name, section.sh_addr, &bytes[off..off + size]);
            }
        }
        Object::PE(pe) => {
            for section in &pe.sections {
                let name = section.name().unwrap_or("?");
                if filter.map_or(false, |f| f != name) {
                    continue;
                }
                let off = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                let vma = section.virtual_address as u64 + pe.image_base as u64;
                print_hex_dump(name, vma, &bytes[off..off + size]);
            }
        }
        _ => eprintln!("(full-contents not supported for this format)"),
    }
    Ok(())
}

// Formato hex identico a objdump -s
fn print_hex_dump(name: &str, base_addr: u64, data: &[u8]) {
    println!();
    println!("Contents of section {name}:");
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_addr + (i * 16) as u64;
        // Colonna hex
        let hex: String = chunk
            .chunks(4)
            .map(|w| w.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .collect::<Vec<_>>()
            .join(" ");
        // Colonna ASCII
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!(" {:08x} {:<40}  {}", addr, hex, ascii);
    }
}

// ── -d / -D / --disassemble ───────────────────────────────────────────────

fn disassemble(bytes: &[u8], config: &Config) -> Result<(), Box<dyn Error>> {
    let filter = config.section_filter.as_deref();

    let sections: Vec<ExecutableSection> = match Object::parse(bytes)? {
        Object::PE(_) => {
            let mut s = PeFormat::parse(bytes)?;
            if !config.disassemble_all {
                s.retain(|sec| filter.map_or(true, |f| sec.name == f));
            }
            s
        }
        Object::Elf(_) => {
            let mut s = ElfFormat::parse(bytes)?;
            if !config.disassemble_all {
                s.retain(|sec| filter.map_or(true, |f| sec.name == f));
            }
            s
        }
        Object::Mach(_) => {
            let mut s = MachoFormat::parse(bytes)?;
            if !config.disassemble_all {
                s.retain(|sec| filter.map_or(true, |f| sec.name == f));
            }
            s
        }
        Object::Unknown(magic) => {
            eprintln!("Unknown format (magic: 0x{magic:x}), raw...");
            vec![ExecutableSection {
                name: "<raw>".into(),
                data: bytes.to_vec(),
                virtual_address: config.adjust_vma,
            }]
        }
        _ => {
            eprintln!("Format not supported, raw...");
            return Ok(());
        }
    };

    if sections.is_empty() {
        eprintln!("No section to disassemble.");
        return Ok(());
    }

    // Determina il bitness dal formato
    let bitness = detect_bitness(bytes);

    for section in sections {
        println!();
        println!("Disassembly of section {}:", section.name);
        println!();
        // Label iniziale identica a objdump: "0000000000401000 <.text>:"
        println!("{:016x} <{}>:", section.virtual_address, section.name);
        let rip = section.virtual_address + config.adjust_vma;
        disasm(bitness, &section.data, rip, &config.instr_format);
    }

    Ok(())
}

fn detect_bitness(bytes: &[u8]) -> u32 {
    match Object::parse(bytes) {
        Ok(Object::Elf(elf)) => {
            if elf.is_64 {
                64
            } else {
                32
            }
        }
        Ok(Object::PE(pe)) => {
            if pe.is_64 {
                64
            } else {
                32
            }
        }
        _ => 64,
    }
}

// ── Flag helpers ──────────────────────────────────────────────────────────

fn section_flags_elf(flags: u64) -> String {
    let mut f = String::new();
    if flags & 0x2 != 0 {
        f.push_str("ALLOC, ");
    }
    if flags & 0x4 != 0 {
        f.push_str("LOAD, ");
    }
    if flags & 0x1 != 0 {
        f.push_str("WRITE, ");
    }
    if flags & 0x4 != 0 {
        f.push_str("EXEC, ");
    }
    if flags & 0x20 != 0 {
        f.push_str("MERGE, ");
    }
    f.trim_end_matches(", ").to_string()
}

fn section_flags_pe(characteristics: u32) -> String {
    let mut f = String::new();
    if characteristics & 0x0000_0020 != 0 {
        f.push_str("CODE, ");
    }
    if characteristics & 0x0000_0040 != 0 {
        f.push_str("DATA, ");
    }
    if characteristics & 0x0200_0000 != 0 {
        f.push_str("DISCARDABLE, ");
    }
    if characteristics & 0x2000_0000 != 0 {
        f.push_str("EXEC, ");
    }
    if characteristics & 0x4000_0000 != 0 {
        f.push_str("READ, ");
    }
    if characteristics & 0x8000_0000 != 0 {
        f.push_str("WRITE, ");
    }
    f.trim_end_matches(", ").to_string()
}
