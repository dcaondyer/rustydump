use crate::config::InstructionFormat;
use crate::demangle::{try_demangle, DemangleStyle};
use crate::disasm::print_symbol_or_label;
use crate::formats::ExecutableSection;
use crate::header::print_ida_section_header;
use crate::symbols::SymbolMap;
use colored::Colorize;
use std::collections::HashMap;
use zydis::{
    ffi::{DecodedOperandKind, MetaInfo}, Decoder, Formatter, FormatterStyle, InstructionCategory, MachineMode,
    StackWidth,
    VisibleOperands,
};

// ─────────────────────────────────────────────────────────────────────────────
// Tipo di salto (speculare al modulo iced)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
pub enum JmpType {
    Call,
    Jmp,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: costruzione decoder / formatter da bitness e stile sintattico
// ─────────────────────────────────────────────────────────────────────────────

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

fn make_formatter(instr_format: &InstructionFormat) -> Formatter {
    match instr_format {
        // Zydis supporta Intel e AT&T natively; per MASM/NASM cadiamo su Intel
        // (comportamento identico al modulo iced che usa IntelFormatter per MASM/NASM)
        InstructionFormat::Intel | InstructionFormat::Masm | InstructionFormat::Nasm => {
            Formatter::new(FormatterStyle::INTEL)
        }
        InstructionFormat::Gas => Formatter::new(FormatterStyle::ATT),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Estrazione indirizzo target + tipo di branch dall'istruzione
// ─────────────────────────────────────────────────────────────────────────────

/// Restituisce `(target_address, JmpType)` se l'istruzione è un branch
/// statico (CALL o qualsiasi tipo di JMP/Jcc).
/// Usa `calc_absolute_address` di Zydis per risolvere operandi RIP-relativi.
pub fn extract_addr_from_instruction(
    inst: &zydis::Instruction<VisibleOperands>,
    ip: u64,
) -> Option<(u64, JmpType)> {
    let meta: &MetaInfo = &inst.meta;

    // Determina il tipo di branch tramite InstructionCategory
    let jmp_type = match meta.category {
        InstructionCategory::CALL => JmpType::Call,
        InstructionCategory::UNCOND_BR | InstructionCategory::COND_BR => JmpType::Jmp,
        _ => return None,
    };

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

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Stampa etichetta / entry point (come print_symbol_or_label nel modulo iced)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Entry point pubblico
// ─────────────────────────────────────────────────────────────────────────────

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

    // ── Primo passaggio: costruiamo le mappe function_entry / jmp_target ──────
    let mut function_entry: HashMap<u64, colored::ColoredString> = HashMap::new();
    let mut jmp_target: HashMap<u64, colored::ColoredString> = HashMap::new();

    if ida_header {
        print_ida_section_header(
            &section.name,
            section.offset,
            section.section_flags,
            &section.object_format,
            true,
        );

        for item in decoder.decode_all::<VisibleOperands>(bytes, code_rip) {
            let (ip, _raw, insn) = match item {
                Ok(x) => x,
                Err(_) => continue,
            };

            if let Some((addr, jmp_type)) = extract_addr_from_instruction(&insn, ip) {
                let label = if let Some(sym_name) = symbols.get(&addr) {
                    let name = try_demangle(sym_name, demangle).unwrap_or_else(|| sym_name.clone());
                    name.bright_green()
                } else {
                    match jmp_type {
                        JmpType::Call => format!("sub_{addr:016X}").bright_green(),
                        JmpType::Jmp => format!("loc_{addr:016X}").bright_green(),
                    }
                };

                match jmp_type {
                    JmpType::Call => {
                        function_entry.insert(addr, label);
                    }
                    JmpType::Jmp => {
                        jmp_target.insert(addr, label);
                    }
                }
            }
        }
    }

    // ── Secondo passaggio: disassembly con output colorato ────────────────────
    for item in decoder.decode_all::<VisibleOperands>(bytes, code_rip) {
        let (ip, raw_bytes, insn) = match item {
            Ok(x) => x,
            Err(_) => continue,
        };

        if ida_header {
            print_symbol_or_label(ip, &function_entry, &jmp_target);
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
        let formatted = match formatter.format(Some(ip), &insn) {
            Ok(s) => s,
            Err(_) => "<format error>".to_string(),
        };

        // Sostituiamo gli indirizzi numerici con i nomi simbolici colorati
        // quando ida_header è abilitato.
        if ida_header {
            if let Some((addr, jmp_type)) = extract_addr_from_instruction(&insn, ip) {
                let sym_colored = if let Some(sym_name) = symbols.get(&addr) {
                    let name = try_demangle(sym_name, demangle).unwrap_or_else(|| sym_name.clone());
                    name.bright_green().to_string()
                } else {
                    match jmp_type {
                        JmpType::Call => format!("sub_{addr:016X}").bright_green().to_string(),
                        JmpType::Jmp => format!("loc_{addr:016X}").bright_green().to_string(),
                    }
                };

                // Sostituiamo l'indirizzo esadecimale nel testo formattato
                // con il nome del simbolo (euristica: cerchiamo l'hex dell'indirizzo).
                let addr_hex_intel = format!("0x{addr:x}");
                let addr_hex_upper = format!("{addr:016X}");
                let patched = if formatted.contains(&addr_hex_intel) {
                    formatted.replacen(&addr_hex_intel, &sym_colored, 1)
                } else if formatted.contains(&addr_hex_upper) {
                    formatted.replacen(&addr_hex_upper, &sym_colored, 1)
                } else {
                    // Nessun match testuale: stampiamo il testo com'è + il nome a fianco
                    format!("{formatted}  {sym_colored}")
                };
                print!("{}", patched);
            } else {
                print!("{}", formatted);
            }
        } else {
            print!("{}", formatted);
        }

        println!();
    }
}
