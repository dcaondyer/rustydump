pub mod output;

use crate::config::InstructionFormat;
use crate::demangle::{try_demangle, DemangleStyle};
use crate::disasm::{construct_entry_and_target, print_symbol_or_label, JmpType};
use crate::formats::ExecutableSection;
use crate::header::print_ida_section_header;
use crate::iced::output::{get_color, MyFormatterOutput};
use crate::symbols::SymbolMap;
use colored::Colorize;
use iced_x86::{
    Decoder, DecoderOptions, Formatter, FormatterTextKind, GasFormatter, Instruction,
    IntelFormatter, MasmFormatter, NasmFormatter, OpKind,
};
use std::collections::{BTreeSet, HashMap};

macro_rules! run_disasm {
    ($formatter:expr, $code_bitness:expr, $section:expr, $code_rip:expr, $demangle:expr, $symbols:expr, $ida_header:expr, $ida_jump:expr, $ida_xrefs:expr) => {{
        $formatter.options_mut().set_first_operand_char_index(8);
        let bytes = &$section.data;
        let mut decoder = Decoder::with_ip($code_bitness, bytes, $code_rip, DecoderOptions::NONE);
        let mut output = MyFormatterOutput::new();
        let mut function_entry = HashMap::new();
        let mut function_xrefs = HashMap::<u64, BTreeSet<u64>>::new();
        let mut jmp_target = HashMap::new();
        let mut jmp_xrefs = HashMap::<u64, BTreeSet<u64>>::new();

        if $ida_header {
            print_ida_section_header(
                &$section.name,
                $section.offset,
                $section.section_flags,
                &$section.object_format,
                true,
            );
        }

        if $ida_jump {
            let mut decoder =
                Decoder::with_ip($code_bitness, bytes, $code_rip, DecoderOptions::NONE);
            for instruction in &mut decoder {
                let ip = instruction.ip();

                output.vec.clear();
                $formatter.format(&instruction, &mut output);
                for (text, kind) in output.vec.iter() {
                    match kind {
                        FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => {
                            let addr =
                                extract_addr_from_instruction(&instruction, text, $code_bitness);
                            if let Some((addr, jmp_type)) = addr {
                                construct_entry_and_target(
                                    addr,
                                    ip,
                                    jmp_type,
                                    $symbols,
                                    $demangle,
                                    &mut function_entry,
                                    &mut jmp_target,
                                    &mut function_xrefs,
                                    &mut jmp_xrefs,
                                    $ida_xrefs,
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        for instruction in &mut decoder {
            // Offset nel buffer = IP corrente - IP base
            let ip = instruction.ip();
            let offset = (ip - $code_rip) as usize;
            let instr_bytes = &bytes[offset..offset + instruction.len()];

            if $ida_jump {
                print_symbol_or_label(
                    ip,
                    &function_entry,
                    &jmp_target,
                    &function_xrefs,
                    &jmp_xrefs,
                    $ida_xrefs,
                );
            }

            // Colonna 1: indirizzo
            print!("{:016X}  ", ip);

            // Colonna 2: stack pointer
            print!("{:08X}  ", instruction.stack_pointer_increment());

            // Colonna 3: bytes dell'istruzione (max 8 byte, con padding)
            // Formato identico a objdump: "48 89 e5" + spazi
            let hex_bytes: String = instr_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            print!("{:<48}    ", hex_bytes); // 48 = 16 byte * 3 chars + spazi

            // Colonna 4: istruzione disassemblata
            output.vec.clear();
            $formatter.format(&instruction, &mut output);
            for (text, kind) in output.vec.iter() {
                // Per gli indirizzi (label o function address), prova a sostituire
                // con il nome del simbolo se disponibile
                let colored = if $ida_jump {
                    match kind {
                        FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => {
                            let addr =
                                extract_addr_from_instruction(&instruction, text, $code_bitness);
                            if let Some((addr, jmp_type)) = addr {
                                match jmp_type {
                                    JmpType::Call => {
                                        if let Some(sym_name) = $symbols.get(&addr) {
                                            let name = try_demangle(sym_name, $demangle)
                                                .unwrap_or_else(|| sym_name.clone());
                                            name.bright_green()
                                        } else {
                                            format!("sub_{addr:016X}").bright_green()
                                        }
                                    }
                                    JmpType::Jmp => {
                                        if let Some(sym_name) = $symbols.get(&addr) {
                                            let name = try_demangle(sym_name, $demangle)
                                                .unwrap_or_else(|| sym_name.clone());
                                            name.bright_green()
                                        } else {
                                            format!("loc_{addr:016X}").bright_green()
                                        }
                                    }
                                }
                            } else {
                                get_color(text, *kind)
                            }
                        }
                        _ => get_color(text, *kind),
                    }
                } else {
                    get_color(text, *kind)
                };

                print!("{}", colored);
            }
            println!();
        }
    }};
}

pub fn disasm(
    code_bitness: u32,
    section: &ExecutableSection,
    code_rip: u64,
    instr_format: &InstructionFormat,
    demangle: DemangleStyle,
    symbols: &SymbolMap,
    ida_header: bool,
    ida_jump: bool,
    ida_xrefs: bool,
) {
    match instr_format {
        InstructionFormat::Intel => run_disasm!(
            IntelFormatter::new(),
            code_bitness,
            section,
            code_rip,
            demangle,
            symbols,
            ida_header,
            ida_jump,
            ida_xrefs
        ),
        InstructionFormat::Gas => run_disasm!(
            GasFormatter::new(),
            code_bitness,
            section,
            code_rip,
            demangle,
            symbols,
            ida_header,
            ida_jump,
            ida_xrefs
        ),
        InstructionFormat::Masm => run_disasm!(
            MasmFormatter::new(),
            code_bitness,
            section,
            code_rip,
            demangle,
            symbols,
            ida_header,
            ida_jump,
            ida_xrefs
        ),
        InstructionFormat::Nasm => run_disasm!(
            NasmFormatter::new(),
            code_bitness,
            section,
            code_rip,
            demangle,
            symbols,
            ida_header,
            ida_jump,
            ida_xrefs
        ),
    }
}

pub fn extract_addr_from_instruction(
    inst: &Instruction,
    text: &str,
    bitness: u32,
) -> Option<(u64, JmpType)> {
    if inst.is_call_near() || inst.is_call_near_indirect() {
        return Some((
            match bitness {
                16 => inst.near_branch16() as u64,
                32 => inst.near_branch32() as u64,
                64 => inst.near_branch64(),
                _ => inst.near_branch_target(),
            },
            JmpType::Call,
        ));
    }

    if inst.is_jmp_near() || inst.is_jmp_near_indirect() {
        return Some((
            match bitness {
                16 => inst.near_branch16() as u64,
                32 => inst.near_branch32() as u64,
                64 => inst.near_branch64(),
                _ => inst.near_branch_target(),
            },
            JmpType::Jmp,
        ));
    }

    if inst.is_call_far() || inst.is_call_far_indirect() {
        return Some((
            match bitness {
                16 => inst.far_branch16() as u64,
                32 => inst.far_branch32() as u64,
                64 => inst.near_branch64(),
                _ => inst.near_branch_target(),
            },
            JmpType::Call,
        ));
    }

    if inst.is_jmp_far() || inst.is_jmp_far_indirect() {
        return Some((
            match bitness {
                16 => inst.far_branch16() as u64,
                32 => inst.far_branch32() as u64,
                64 => inst.near_branch64(),
                _ => inst.near_branch_target(),
            },
            JmpType::Jmp,
        ));
    }

    if inst.op_count() > 0 {
        for i in 0..inst.op_count() {
            match inst.op_kind(i) {
                OpKind::NearBranch64 => return Some((inst.near_branch64(), JmpType::Jmp)),
                OpKind::NearBranch32 => return Some((inst.near_branch32() as u64, JmpType::Jmp)),
                OpKind::NearBranch16 => return Some((inst.near_branch16() as u64, JmpType::Jmp)),
                OpKind::FarBranch32 => return Some((inst.far_branch32() as u64, JmpType::Jmp)),
                OpKind::FarBranch16 => return Some((inst.far_branch16() as u64, JmpType::Jmp)),

                OpKind::Memory => {
                    if inst.is_ip_rel_memory_operand() {
                        return Some((inst.ip_rel_memory_address(), JmpType::Jmp));
                    }

                    let disp = match bitness {
                        32 => inst.memory_displacement32() as u64,
                        64 => inst.memory_displacement64(),
                        _ => 0,
                    };

                    if disp != 0 {
                        return Some((disp, JmpType::Jmp));
                    }

                    let base = inst.memory_base();
                    if !base.is_ip() {
                        continue;
                    }
                }

                OpKind::Register => {
                    continue;
                }

                _ => continue,
            }
        }
    }

    let clean = text
        .trim()
        .trim_end_matches(['h', 'H'])
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .replace(['_', ','], "")
        .replace("ptr", "")
        .replace("near", "")
        .trim()
        .to_string();

    if let Ok(val) = u64::from_str_radix(&clean, 16) {
        return Some((val, JmpType::Jmp));
    }

    if let Ok(val) = clean.parse::<u64>() {
        return Some((val, JmpType::Jmp));
    }

    None
}
