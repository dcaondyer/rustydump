use crate::config::InstructionFormat;
use colored::{ColoredString, Colorize};
use zydis::FormatterStyle;
use zydis::{Formatter, Token};

pub fn make_formatter(instr_format: &InstructionFormat) -> Formatter {
    match instr_format {
        // Zydis supporta Intel e AT&T natively; per MASM/NASM cadiamo su Intel
        // (comportamento identico al modulo iced che usa IntelFormatter per MASM/NASM)
        InstructionFormat::Intel | InstructionFormat::Masm | InstructionFormat::Nasm => {
            Formatter::new(FormatterStyle::INTEL)
        }
        InstructionFormat::Gas => Formatter::new(FormatterStyle::ATT),
    }
}

pub fn get_color(s: &str, token: Token) -> ColoredString {
    // I valori u8 corrispondono alle costanti ZYDIS_TOKEN_* della C lib:
    //   0x01 = WHITESPACE, 0x02 = DELIMITER, 0x03 = PARENTHESIS_OPEN
    //   0x04 = PARENTHESIS_CLOSE, 0x05 = PREFIX, 0x06 = MNEMONIC
    //   0x07 = REGISTER, 0x08 = ADDRESS_ABS, 0x09 = ADDRESS_REL
    //   0x0A = DISPLACEMENT, 0x0B = IMMEDIATE, 0x0C = TYPECAST
    //   0x0D = DECORATOR, 0x0E = SYMBOL
    match token.0 {
        0x06 => s.bright_red(),          // MNEMONIC  → come Prefix/Mnemonic in iced
        0x05 => s.bright_red(),          // PREFIX    → idem
        0x07 => s.bright_blue(),         // REGISTER  → come Register in iced
        0x08 | 0x09 => s.bright_green(), // ADDRESS_ABS / ADDRESS_REL → come LabelAddress/FunctionAddress
        0x0A | 0x0B => s.bright_cyan(),  // DISPLACEMENT / IMMEDIATE → come Number
        0x0C => s.bright_yellow(),       // TYPECAST  → come Directive/Keyword
        0x0E => s.bright_green(),        // SYMBOL    → come FunctionAddress
        _ => s.white(),                  // tutto il resto (punteggiatura, spazi, ecc.)
    }
}
