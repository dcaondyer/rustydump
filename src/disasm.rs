use crate::config::InstructionFormat;
use crate::demangle::DemangleStyle;
use crate::formats::ExecutableSection;
use crate::iced;
use crate::symbols::SymbolMap;
use crate::zydis;
use colored::ColoredString;
use std::collections::HashMap;

const PAD: &str =
    "                                                                                ";

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

pub fn print_symbol_or_label(
    ip: u64,
    function_entry: &HashMap<u64, ColoredString>,
    jmp_target: &HashMap<u64, ColoredString>,
) {
    let mut is_function: bool = false;

    // Esci se non c'e' nel database degli entry point
    if !function_entry.contains_key(&ip) && !jmp_target.contains_key(&ip) {
        return;
    }

    if let Some(name) = function_entry.get(&ip) {
        println!();
        println!("{}{}:", PAD, name);
        is_function = true;
    }

    if let Some(name) = jmp_target.get(&ip) {
        if !is_function {
            println!();
        }
        println!("{}{}:", PAD, name);
    }
}
