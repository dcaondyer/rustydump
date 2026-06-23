use crate::config::InstructionFormat;
use crate::output::{get_color, MyFormatterOutput};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, GasFormatter, IntelFormatter, MasmFormatter, NasmFormatter,
};

macro_rules! run_disasm {
    ($formatter:expr, $bitness:expr, $bytes:expr, $rip:expr) => {{
        $formatter.options_mut().set_first_operand_char_index(8);
        let mut decoder = Decoder::with_ip($bitness, $bytes, $rip, DecoderOptions::NONE);
        let mut output = MyFormatterOutput::new();

        for instruction in &mut decoder {
            print!("{:016x}  ", instruction.ip());
            output.vec.clear();
            $formatter.format(&instruction, &mut output);
            for (text, kind) in output.vec.iter() {
                print!("{}", get_color(text.as_str(), *kind));
            }
            println!();
        }
    }};
}

pub fn disasm(code_bitness: u32, bytes: &[u8], code_rip: u64, instr_format: &InstructionFormat) {
    match instr_format {
        InstructionFormat::Intel => {
            run_disasm!(IntelFormatter::new(), code_bitness, bytes, code_rip)
        }
        InstructionFormat::Gas => run_disasm!(GasFormatter::new(), code_bitness, bytes, code_rip),
        InstructionFormat::Masm => run_disasm!(MasmFormatter::new(), code_bitness, bytes, code_rip),
        InstructionFormat::Nasm => run_disasm!(NasmFormatter::new(), code_bitness, bytes, code_rip),
    }
}
