pub mod analysis;
pub mod config;
pub mod decode;
pub mod demangle;
pub mod detection;
pub mod disasm;
pub mod formats;
pub mod header;
pub mod iced;
pub mod symbols;
pub mod zydis;

use crate::analysis::construct_cfg;
use crate::config::Config;
use crate::disasm::disasm;
use crate::formats::{
    elf::ElfFormat, macho::MachoFormat, pe::PeFormat, BinaryFormat, ExecutableSection,
};
use crate::header::print_ida_file_header;
use crate::symbols::SymbolMap;
use goblin::mach::{Mach, SingleArch};
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
        if config.ida_header {
            print_ida_file_header(&bytes, file)?;
        }
        disassemble(&bytes, config, symbols::build_symbol_map(&bytes))?;
    }

    if config.build_cfg || config.cfg_dot.is_some() {
        let bitness = detect_bitness(&bytes);
        let sections: Vec<ExecutableSection> = match Object::parse(&bytes)? {
            Object::PE(_) => PeFormat::parse(&bytes)?,
            Object::Elf(_) => ElfFormat::parse(&bytes)?,
            Object::Mach(_) => MachoFormat::parse(&bytes)?,
            _ => vec![],
        };

        for section in &sections {
            println!("\nCFG for section: {}", section.name);

            // Se --cfg-dot, costruisci path per-sezione: out.dot → out_text.dot
            let dot_path = config.cfg_dot.as_ref().map(|base| {
                let stem = base.file_stem().unwrap_or_default().to_string_lossy();
                let safe = section.name.replace(['.', '/'], "_");
                base.with_file_name(format!("{}_{}.dot", stem, safe))
            });

            construct_cfg(section, bitness, config.backend, dot_path.as_deref())?;
        }
    }

    Ok(())
}

/// Rivela il formato del binario
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

/// -f / --file-headers
struct FileHeader {
    arch: &'static str,
    flags: u32,
    start_address: u64,
}

impl FileHeader {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        match Object::parse(bytes)? {
            Object::Elf(elf) => Ok(Self {
                arch: if elf.is_64 { "i386:x86-64" } else { "i386" },
                flags: elf.header.e_flags,
                start_address: elf.entry,
            }),
            Object::PE(pe) => Ok(Self {
                arch: if pe.is_64 { "i386:x86-64" } else { "i386" },
                flags: pe.header.coff_header.characteristics as u32,
                start_address: pe.entry as u64 + pe.image_base as u64,
            }),
            Object::Mach(mach) => {
                let (flags, start_address, arch) = match mach {
                    Mach::Binary(m) => (
                        m.header.flags,
                        m.entry,
                        if m.is_64 { "i386:x86-64" } else { "i386" },
                    ),
                    Mach::Fat(fat) => {
                        // Prendi la prima architettura disponibile per i metadati
                        let first = fat.into_iter().filter_map(|a| a.ok()).find_map(|a| {
                            if let SingleArch::MachO(m) = a {
                                Some(m)
                            } else {
                                None
                            }
                        });
                        match first {
                            Some(m) => (
                                m.header.flags,
                                m.entry,
                                if m.is_64 {
                                    "i386:x86-64 (fat)"
                                } else {
                                    "i386 (fat)"
                                },
                            ),
                            None => (0u32, 0u64, "unknown (fat)"),
                        }
                    }
                };
                Ok(Self {
                    arch,
                    flags,
                    start_address,
                })
            }
            _ => Err("Unsupported format".into()),
        }
    }
}

fn print_file_headers(bytes: &[u8], file: &PathBuf) -> Result<(), Box<dyn Error>> {
    println!();
    match FileHeader::from_bytes(bytes) {
        Ok(hdr) => {
            println!("{}:", file.display());
            println!("architecture: {}", hdr.arch);
            println!("flags:        0x{:08x}", hdr.flags);
            println!("start address 0x{:016x}", hdr.start_address);
        }
        Err(_) => println!("(header not present)"),
    }
    Ok(())
}

/// -h / --section-headers
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

/// -p / --private-headers
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

/// -t / --syms
fn print_symbol_table(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    println!();
    println!("SYMBOL TABLE:");
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            if elf.syms.iter().len() == 0 {
                println!("(symbol table is empty)");
            }
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
            if pe.exports.len() == 0 {
                println!("(symbol table is empty)");
            }
            for sym in &pe.exports {
                println!(
                    "{:016x} g F {:016x} {}",
                    sym.rva as u64 + pe.image_base as u64,
                    sym.size as u64,
                    sym.name.unwrap_or("?")
                );
            }
        }
        Object::Mach(mach) => {
            if let Mach::Binary(m) = mach {
                match &m.symbols {
                    None => println!("(symbol table is empty)"),
                    Some(symbols) => {
                        let syms: Vec<_> = symbols
                            .into_iter()
                            .filter_map(|res| res.ok()) // scarta gli Err
                            .filter(|(name, _)| !name.is_empty())
                            .collect();

                        if syms.is_empty() {
                            println!("(symbol table is empty)");
                        } else {
                            for (name, nlist) in syms {
                                println!("{:016x}   {:016x} {}", nlist.n_value, 0u64, name);
                            }
                        }
                    }
                }
            }
        }
        _ => println!("(symbol table not present)"),
    }
    Ok(())
}

/// -T / --dynamic-syms
fn print_dynamic_syms(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    println!();
    println!("DYNAMIC SYMBOL TABLE:");
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            if elf.dynsyms.iter().len() == 0 {
                println!("(dynamic symbol table is empty)");
            }
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
            if pe.imports.len() == 0 {
                println!("(dynamic symbol table is empty)");
            }
            for import in &pe.imports {
                println!(
                    "{:016x} g F {:016x} {}",
                    import.rva as u64, import.size, import.name
                );
            }
        }
        Object::Mach(mach) => {
            if let Mach::Binary(m) = mach {
                // Export trie — più affidabile per i simboli dinamici
                match m.exports() {
                    Err(_) => println!("(dynamic exports symbol table is empty)"),
                    Ok(exports) => {
                        if exports.is_empty() {
                            println!("(dynamic exports symbol table is empty)");
                        } else {
                            for export in exports {
                                if export.size != 0 {
                                    println!(
                                        "{:016x}   {:016x} {}",
                                        export.offset,
                                        0u64,
                                        export.name.to_string()
                                    );
                                }
                            }
                        }
                    }
                }

                // Import — simboli dinamici da librerie esterne
                match m.imports() {
                    Err(_) => println!("(dynamic symbol table is empty)"),
                    Ok(imports) => {
                        if imports.is_empty() {
                            println!("(dynamic symbol table is empty)");
                        } else {
                            for import in imports {
                                if import.size != 0 {
                                    println!(
                                        "{:016x}   {:016x} {}",
                                        import.offset,
                                        0u64,
                                        import.name.to_string()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => println!("(dynamic symbol table not present)"),
    }
    Ok(())
}

///-s / --full-contents
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

/// Formato hex identico a objdump -s
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

/// -d / -D / --disassemble
fn disassemble(bytes: &[u8], config: &Config, symbols: SymbolMap) -> Result<(), Box<dyn Error>> {
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
                offset: 0u64,
                size: 0u64,
                section_flags: None,
                object_format: None,
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
        disasm(
            bitness,
            &section,
            rip,
            &config.instr_format,
            config.demangle, // DemangleStyle::None se -C non passato
            &symbols,
            config.decoder,
            config.ida_header,
            config.ida_jump,
            config.ida_xrefs,
        );
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

/// Flag helpers
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
