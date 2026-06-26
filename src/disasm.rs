use crate::config::InstructionFormat;
use crate::demangle::{try_demangle, DemangleStyle};
use crate::formats::ExecutableSection;
use crate::iced;
use crate::symbols::SymbolMap;
use crate::zydis;
use colored::{ColoredString, Colorize};
use std::collections::{BTreeSet, HashMap};

const PAD: &str =
    "                                                                                ";

#[derive(PartialEq)]
pub enum JmpType {
    Call,
    Jmp,
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum DecoderKind {
    #[default]
    Iced,
    Zydis,
}

pub fn disasm(
    code_bitness: u32,
    section: &ExecutableSection,
    code_rip: u64,
    instr_format: &InstructionFormat,
    demangle: DemangleStyle,
    symbols: &SymbolMap,
    ida_header: bool,
    decoder: DecoderKind,
) {
    match decoder {
        DecoderKind::Iced => iced::disasm(
            code_bitness,
            section,
            code_rip,
            instr_format,
            demangle,
            symbols,
            ida_header,
        ),
        DecoderKind::Zydis => zydis::disasm(
            code_bitness,
            section,
            code_rip,
            instr_format,
            demangle,
            symbols,
            ida_header,
        ),
    };
}

pub fn construct_entry_and_target(
    addr: u64,
    ip: u64,
    jmp_type: JmpType,
    symbols: &SymbolMap,
    demangle: DemangleStyle,
    function_entry: &mut HashMap<u64, ColoredString>,
    jmp_target: &mut HashMap<u64, ColoredString>,
    function_xrefs: &mut HashMap<u64, BTreeSet<u64>>,
    jmp_xrefs: &mut HashMap<u64, BTreeSet<u64>>,
) {
    match jmp_type {
        JmpType::Call => {
            if let Some(sym_name) = symbols.get(&addr) {
                let name = try_demangle(sym_name, demangle).unwrap_or_else(|| sym_name.clone());
                let name = name.bright_green();
                function_entry.insert(addr, name);
            } else {
                function_entry.insert(addr, format!("sub_{addr:016X}").bright_green());
            }
            match function_xrefs.remove(&addr) {
                Some(mut xrefs) => {
                    xrefs.insert(ip);
                    function_xrefs.insert(addr, xrefs);
                }
                None => {
                    function_xrefs.insert(addr, BTreeSet::new());
                }
            }
        }
        JmpType::Jmp => {
            if let Some(sym_name) = symbols.get(&addr) {
                let name = try_demangle(sym_name, demangle).unwrap_or_else(|| sym_name.clone());
                let name = name.bright_green();
                jmp_target.insert(addr, name);
            } else {
                jmp_target.insert(addr, format!("loc_{addr:016X}").bright_green());
            }
            match jmp_xrefs.remove(&addr) {
                Some(mut xrefs) => {
                    xrefs.insert(ip);
                    jmp_xrefs.insert(addr, xrefs);
                }
                None => {
                    jmp_xrefs.insert(addr, BTreeSet::new());
                }
            }
        }
    }
}

pub fn print_symbol_or_label(
    ip: u64,
    function_entry: &HashMap<u64, ColoredString>,
    jmp_target: &HashMap<u64, ColoredString>,
    function_xrefs: &HashMap<u64, BTreeSet<u64>>,
    jmp_xrefs: &HashMap<u64, BTreeSet<u64>>,
) {
    let mut is_function: bool = false;
    let mut is_jmp: bool = false;

    // Esci se non c'e' nel database degli entry point
    if !function_entry.contains_key(&ip) && !jmp_target.contains_key(&ip) {
        return;
    }

    if let Some(name) = function_entry.get(&ip) {
        println!();
        println!("{}{}:", PAD, name);
        is_function = true;
    }

    if is_function && let Some(xrefs) = function_xrefs.get(&ip) {
        let mut it = xrefs.iter().peekable();

        if let Some(first) = it.next() {
            println!(
                "{}{}{}",
                PAD,
                "xrefs: ".purple(),
                format!("0x{:016X}", first).to_string().bright_yellow()
            );
        }
        for xref in it {
            println!(
                "{}{}{}",
                PAD,
                "       ".purple(),
                format!("0x{:016X}", xref).to_string().bright_yellow()
            );
        }
    }

    if let Some(name) = jmp_target.get(&ip) {
        if !is_function {
            println!();
        }
        println!("{}{}:", PAD, name);
        is_jmp = true;
    }

    if is_jmp && let Some(xrefs) = jmp_xrefs.get(&ip) {
        let mut it = xrefs.iter().peekable();

        if let Some(first) = it.next() {
            println!(
                "{}{}{}",
                PAD,
                "xrefs: ".purple(),
                format!("0x{:016X}", first).to_string().bright_yellow()
            );
        }
        for xref in it {
            println!(
                "{}{}{}",
                PAD,
                "       ".purple(),
                format!("0x{:016X}", xref).to_string().bright_yellow()
            );
        }
    }
}
