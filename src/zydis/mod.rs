pub mod output;

use crate::config::InstructionFormat;
use crate::demangle::{try_demangle, DemangleStyle};
use crate::disasm::{construct_entry_and_target, print_symbol_or_label, JmpType};
use crate::formats::ExecutableSection;
use crate::header::print_ida_section_header;
use crate::symbols::SymbolMap;
use crate::zydis::output::{get_color, make_formatter};
use colored::Colorize;
use std::collections::{BTreeSet, HashMap};
use zydis::ffi::DecodedOperandKind;
use zydis::{Decoder, InstructionCategory, MachineMode, StackWidth, VisibleOperands};

fn make_decoder(code_bitness: u32) -> Decoder {
    match code_bitness {
        16 => {
            Decoder::new(MachineMode::LONG_COMPAT_16, StackWidth::_16).expect("decoder 16-bit init")
        }
        32 => {
            Decoder::new(MachineMode::LONG_COMPAT_32, StackWidth::_32).expect("decoder 32-bit init")
        }
        _ => Decoder::new64(),
    }
}

/// Restituisce `(target_address, JmpType)` se l'istruzione è un branch
/// statico (CALL o qualsiasi tipo di JMP/Jcc).
/// Usa `calc_absolute_address` di Zydis per risolvere operandi RIP-relativi.
pub fn extract_addr_from_instruction(
    inst: &zydis::Instruction<VisibleOperands>,
    ip: u64,
) -> Option<(u64, JmpType)> {
    let meta = &inst.meta;

    let jmp_type = match meta.category {
        InstructionCategory::CALL => JmpType::Call,
        InstructionCategory::UNCOND_BR | InstructionCategory::COND_BR => JmpType::Jmp,
        _ => return None,
    };

    // 1. CASO MIGLIORE: branch diretto già risolto dal decoder
    // Cerca il primo operando che ha un indirizzo calcolabile
    for op in inst.operands() {
        match &op.kind {
            // Operando immediato/branch diretto
            DecodedOperandKind::Imm(_) | DecodedOperandKind::Ptr(_) => {
                if let Ok(addr) = inst.calc_absolute_address(ip, op) {
                    return Some((addr, jmp_type));
                }
            }
            // Memoria RIP-relativa (es. `call [rip + disp]`)
            DecodedOperandKind::Mem(mem) => {
                if let Ok(addr) = inst.calc_absolute_address(ip, op) {
                    // Accettiamo solo se c'è effettivamente un displacement
                    // oppure la base è RIP (calc_absolute_address già lo gestisce)
                    let _ = mem; // usata implicitamente sopra
                    return Some((addr, jmp_type));
                }
            }
            // Registro puro: nessun target statico
            DecodedOperandKind::Reg(_) | DecodedOperandKind::Unused => continue,
        }
    }

    // 2. FALLBACK: immediato puro (JMP/CALL rel32/rel64)
    if let Some(op) = inst
        .operands()
        .iter()
        .find(|o| matches!(o.kind, DecodedOperandKind::Imm(_)))
    {
        if let Ok(addr) = inst.calc_absolute_address(ip, op) {
            return Some((addr, jmp_type));
        }
    }

    None
}

pub fn disasm(
    code_bitness: u32,
    section: &ExecutableSection,
    code_rip: u64,
    instr_format: &InstructionFormat,
    demangle: DemangleStyle,
    symbols: &SymbolMap,
    ida_header: bool,
) {
    let decoder = make_decoder(code_bitness);
    let formatter = make_formatter(instr_format);
    let bytes = &section.data;

    let mut function_entry = HashMap::new();
    let mut function_xrefs = HashMap::<u64, BTreeSet<u64>>::new();
    let mut jmp_target = HashMap::new();
    let mut jmp_xrefs = HashMap::<u64, BTreeSet<u64>>::new();

    if ida_header {
        print_ida_section_header(
            &section.name,
            section.offset,
            section.section_flags,
            &section.object_format,
            true,
        );

        for item in decoder.decode_all(bytes, code_rip) {
            let (ip, _raw_bytes, inst) = match item {
                Ok(x) => x,
                Err(_) => continue,
            };

            if let Some((addr, jmp_type)) = extract_addr_from_instruction(&inst, ip) {
                construct_entry_and_target(
                    addr,
                    ip,
                    jmp_type,
                    symbols,
                    demangle,
                    &mut function_entry,
                    &mut jmp_target,
                    &mut function_xrefs,
                    &mut jmp_xrefs,
                );
            }
        }
    }

    for item in decoder.decode_all::<VisibleOperands>(bytes, code_rip) {
        let (ip, raw_bytes, inst) = match item {
            Ok(x) => x,
            Err(_) => continue,
        };

        if ida_header {
            print_symbol_or_label(
                ip,
                &function_entry,
                &jmp_target,
                &function_xrefs,
                &jmp_xrefs,
            );
        }

        // Colonna 1: indirizzo virtuale
        print!("{:016X}  ", ip);

        // Colonna 2: stack pointer increment (Zydis non espone questo campo
        // nella versione pubblica della struct; usiamo 0 come placeholder —
        // sostituire con la logica desiderata se necessario)
        print!("{:08X}  ", 0u32);

        // Colonna 3: bytes grezzi (padding a 48 caratteri come nel modulo iced)
        let hex_bytes: String = raw_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        print!("{:<48}    ", hex_bytes);

        // Colonna 4: istruzione disassemblata + colorazione simboli
        //let formatted = match formatter.format(Some(ip), &inst) {
        //    Ok(s) => s,
        //    Err(_) => "<format error>".to_string(),
        //};

        // Sostituiamo gli indirizzi numerici con i nomi simbolici colorati
        // quando ida_header è abilitato.
        //if ida_header {
        //    if let Some((addr, jmp_type)) = extract_addr_from_instruction(&inst, ip) {
        //        let sym_colored = if let Some(sym_name) = symbols.get(&addr) {
        //            let name = try_demangle(sym_name, demangle).unwrap_or_else(|| sym_name.clone());
        //            name.bright_green().to_string()
        //        } else {
        //            match jmp_type {
        //                JmpType::Call => format!("sub_{addr:016X}").bright_green().to_string(),
        //                JmpType::Jmp => format!("loc_{addr:016X}").bright_green().to_string(),
        //            }
        //        };

        //        // Sostituiamo l'indirizzo esadecimale nel testo formattato
        //        // con il nome del simbolo (euristica: cerchiamo l'hex dell'indirizzo).
        //        let addr_hex_intel = format!("0x{addr:016x}");
        //        let addr_hex_intel_upper = format!("0x{addr:016X}");
        //        let addr_hex = format!("{addr:016x}");
        //        let addr_hex_upper = format!("{addr:016X}");

        //        let patched = if formatted.contains(&addr_hex_intel) {
        //            formatted.replacen(&addr_hex_intel, &sym_colored, 1)
        //        } else if formatted.contains(&addr_hex_intel_upper) {
        //            formatted.replacen(&addr_hex_intel_upper, &sym_colored, 1)
        //        } else if formatted.contains(&addr_hex) {
        //            formatted.replacen(&addr_hex, &sym_colored, 1)
        //        } else if formatted.contains(&addr_hex_upper) {
        //            formatted.replacen(&addr_hex_upper, &sym_colored, 1)
        //        } else {
        //            // Nessun match testuale: stampiamo il testo com'è + il nome a fianco
        //            format!("{formatted}  {sym_colored}")
        //        };

        //        print!("{}", patched);
        //    } else {
        //        print!("{}", formatted);
        //    }
        //} else {
        //    print!("{}", formatted);
        //}

        const N: usize = 5;
        const BUF_SIZE: usize = 256; // Raccomandato dalla documentazione
        let mut buf = [0u8; BUF_SIZE];

        // Colonna 4: istruzione disassemblata con colorazione per token
        let formatted_colored: String =
            match formatter.tokenize::<N>(Some(ip), &inst, &mut buf, None) {
                Ok(first_token) => {
                    let branch_info = if ida_header {
                        extract_addr_from_instruction(&inst, ip)
                    } else {
                        None
                    };

                    first_token
                        .into_iter()
                        .map(|(token, text)| {
                            // Se è un indirizzo assoluto e abbiamo un simbolo, sostituiamo
                            if token.0 == 0x08 || token.0 == 0x09 {
                                if let Some((addr, ref jmp_type)) = branch_info {
                                    if let Some(sym_name) = symbols.get(&addr) {
                                        let name = try_demangle(sym_name, demangle)
                                            .unwrap_or_else(|| sym_name.clone());
                                        return name.bright_green().to_string();
                                    } else {
                                        return match jmp_type {
                                            JmpType::Call => format!("sub_{addr:016X}")
                                                .bright_green()
                                                .to_string(),
                                            JmpType::Jmp => format!("loc_{addr:016X}")
                                                .bright_green()
                                                .to_string(),
                                        };
                                    }
                                }
                            }
                            get_color(text, token).to_string()
                        })
                        .collect()
                }
                Err(_) => "<format error>".white().to_string(),
            };

        print!("{}", formatted_colored);
        println!();
    }
}
