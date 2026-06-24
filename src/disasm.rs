use crate::config::InstructionFormat;
use crate::demangle::{try_demangle, DemangleStyle};
use crate::formats::ExecutableSection;
use crate::header::print_ida_section_header;
use crate::output::{get_color, MyFormatterOutput};
use crate::symbols::SymbolMap;
use colored::{ColoredString, Colorize};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, FormatterTextKind, GasFormatter, IntelFormatter,
    MasmFormatter, NasmFormatter,
};

macro_rules! run_disasm {
    ($formatter:expr, $code_bitness:expr, $section:expr, $code_rip:expr, $demangle:expr, $symbols:expr, $ida_header:expr) => {{
        $formatter.options_mut().set_first_operand_char_index(8);
        let bytes = &$section.data;
        let mut decoder = Decoder::with_ip($code_bitness, bytes, $code_rip, DecoderOptions::NONE);
        let mut output = MyFormatterOutput::new();

        // Header stile IDA Pro
        if $ida_header {
            print_ida_section_header(
                &$section.name,
                $section.offset,
                $section.section_flags,
                &$section.object_format,
                true,
            );
        }

        for instruction in &mut decoder {
            // Offset nel buffer = IP corrente - IP base
            let ip = instruction.ip();
            let offset = (ip - $code_rip) as usize;
            let instr_bytes = &bytes[offset..offset + instruction.len()];

            // ── Label simbolo (se presente nella symbol table) ────────
            if let Some(sym_name) = $symbols.get(&ip) {
                let label = match try_demangle(sym_name, $demangle) {
                    Some(d) => d,
                    None => format!("sub_{ip:08X}"),
                };
                println!();
                println!("{}:", label.bright_green());
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
                let colored = match kind {
                    FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => {
                        // Il testo è tipo "00000001400598E0h" o "0x1400598E0"
                        // Proviamo a parsarlo come indirizzo
                        if let Some(name) = resolve_address(text, $symbols, $demangle) {
                            name.bright_green()
                        } else {
                            get_color(text, *kind)
                        }
                    }
                    _ => get_color(text, *kind),
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
    symbols: &SymbolMap, // mappa addr → nome simbolo
    ida_header: bool,
) {
    match instr_format {
        InstructionFormat::Intel => run_disasm!(
            IntelFormatter::new(),
            code_bitness,
            section,
            code_rip,
            demangle,
            symbols,
            ida_header
        ),
        InstructionFormat::Gas => run_disasm!(
            GasFormatter::new(),
            code_bitness,
            section,
            code_rip,
            demangle,
            symbols,
            ida_header
        ),
        InstructionFormat::Masm => run_disasm!(
            MasmFormatter::new(),
            code_bitness,
            section,
            code_rip,
            demangle,
            symbols,
            ida_header
        ),
        InstructionFormat::Nasm => run_disasm!(
            NasmFormatter::new(),
            code_bitness,
            section,
            code_rip,
            demangle,
            symbols,
            ida_header
        ),
    }
}

fn resolve_address(
    text: &str,
    symbols: &SymbolMap,
    demangle: DemangleStyle,
) -> Option<ColoredString> {
    // Normalizza il testo rimuovendo suffissi come 'h' (MASM) e prefissi '0x'
    let clean = text
        .trim()
        .trim_end_matches('h')
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .replace('_', "");

    let addr = u64::from_str_radix(&clean, 16).ok()?;
    let raw_name = symbols.get(&addr)?;

    let display_name =
        try_demangle(raw_name, demangle).unwrap_or_else(|| format!("sub_{addr:08X}"));

    Some(display_name.bright_green())
}
