use crate::decode::BackendKind;
use crate::demangle::DemangleStyle;
use crate::disasm::DecoderKind;
use clap::{ArgGroup, Parser};
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, Default, PartialEq, clap::ValueEnum)]
pub enum InstructionFormat {
    #[default]
    Intel,
    Gas, // AT&T syntax (default di objdump GNU)
    Masm,
    Nasm,
}

impl std::str::FromStr for InstructionFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "intel" => Ok(Self::Intel),
            "att" | "gas" => Ok(Self::Gas),
            "masm" => Ok(Self::Masm),
            "nasm" => Ok(Self::Nasm),
            other => Err(format!(
                "unknown dialect '{other}'. Valid values: intel, att, masm, nasm"
            )),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
     name    = "rustydump",
     version = {VERSION},
     about   = "Display, analyze and disassemble object files",
     long_about = "Rustydump is a modern, objdump-compatible binary analysis tool written in Rust for i386 and amd64.
It supports disassembly, symbol inspection, section/header parsing, and control-flow graph generation [EXPERIMENTAL] for multiple object file formats.
It features selectable disassembly backends (iced-x86 and Zydis) and optional IDA-style enhanced output including labels and cross-references.",
     group = ArgGroup::new("action")
         .args([
             "disassemble", "disassemble_all", "file_headers",
             "section_headers", "all_headers", "full_contents",
             "syms", "dynamic_syms", "private_headers",
         ])
         .required(true)
         .multiple(true),
)]
pub struct Config {
    #[arg(
        value_name = "FILE",
        required = true,
        help = "Object file(s) to examine"
    )]
    pub files: Vec<PathBuf>,

    #[arg(
        short = 'd',
        long = "disassemble",
        help = "Disassemble executable sections",
        group = "action"
    )]
    pub disassemble: bool,

    #[arg(
        short = 'D',
        long = "disassemble-all",
        help = "Disassemble all sections",
        group = "action"
    )]
    pub disassemble_all: bool,

    #[arg(
        short = 'f',
        long = "file-headers",
        help = "Display the contents of the overall file header",
        group = "action"
    )]
    pub file_headers: bool,

    #[arg(
        short = 'h',
        long = "section-headers",
        visible_alias = "headers",
        help = "Display the contents of the section headers",
        group = "action"
    )]
    pub section_headers: bool,

    #[arg(
        short = 'x',
        long = "all-headers",
        help = "Display all available header information (-f -h -p -t combined)",
        group = "action"
    )]
    pub all_headers: bool,

    #[arg(
        short = 's',
        long = "full-contents",
        help = "Display the full contents of all sections (hex dump)",
        group = "action"
    )]
    pub full_contents: bool,

    #[arg(
        short = 'p',
        long = "private-headers",
        help = "Display format-specific file header contents",
        group = "action"
    )]
    pub private_headers: bool,

    #[arg(
        short = 't',
        long = "syms",
        help = "Display the symbol table",
        group = "action"
    )]
    pub syms: bool,

    #[arg(
        short = 'T',
        long = "dynamic-syms",
        help = "Display the dynamic symbol table",
        group = "action"
    )]
    pub dynamic_syms: bool,

    #[arg(
        short = 'S',
        long = "source",
        help = "Intermix source code with disassembly (implies -d)"
    )]
    pub source: bool,

    #[arg(
        short = 'j',
        long = "section",
        value_name = "NAME",
        help = "Only display information for section NAME"
    )]
    pub section_filter: Option<String>,

    #[arg(
        short = 'M',
        long = "disassembler-options",
        value_name = "OPT",
        default_value = "intel",
        help = "Pass target specific information to the disassembler"
    )]
    pub instr_format: InstructionFormat,

    #[arg(
        short = 'I',
        long = "ida-all",
        help = "Total IDA Pro-style (-H -J -X combined)"
    )]
    pub ida_all: bool,

    #[arg(
        short = 'H',
        long = "ida-header",
        help = "Print an IDA Pro-style header before each section listing"
    )]
    pub ida_header: bool,

    #[arg(
        short = 'J',
        long = "ida-jump",
        help = "Print IDA Pro-style sub_00000000 and loc_00000000"
    )]
    pub ida_jump: bool,

    #[arg(
        short = 'X',
        long = "ida-xrefs",
        help = "Print IDA Pro-style xrefs (implies -J)"
    )]
    pub ida_xrefs: bool,

    #[arg(
        long  = "adjust-vma",
        value_name = "OFFSET",
        default_value = "0",
        value_parser = parse_hex_or_dec,
        help  = "Add OFFSET to all displayed section addresses",
    )]
    pub adjust_vma: u64,

    #[arg(
        short = 'C',
        long  = "demangle",
        value_name = "STYLE",
        num_args = 0..=1,           // -C da solo oppure -C=rust / -C=cpp
        default_value = "none",
        default_missing_value = "auto",
        help  = "Decode symbol names [auto|rust|cpp|none]",
    )]
    pub demangle: DemangleStyle,

    #[arg(
        short = 'B',
        long = "decoder",
        value_name = "DECODER",
        default_value = "iced",
        help = "Decoder backend to use for disassembly"
    )]
    pub decoder: DecoderKind,

    #[arg(
        long = "cfg",
        help = "Build and print the Control Flow Graph of executable sections [EXPERIMENTAL]",
        group = "action"
    )]
    pub build_cfg: bool,

    #[arg(
        long = "cfg-dot",
        value_name = "FILE",
        help = "Export CFG as Graphviz DOT file (e.g. --cfg-dot=out.dot) [EXPERIMENTAL]",
        group = "action"
    )]
    pub cfg_dot: Option<PathBuf>,

    #[arg(
        long = "cfg-backend",
        value_name = "BACKEND",
        default_value = "iced",
        help = "Decoder backend to use for CFG construction [EXPERIMENTAL]"
    )]
    pub backend: BackendKind,
}

impl Config {
    pub fn normalize(&mut self) {
        if self.all_headers {
            self.file_headers = true;
            self.section_headers = true;
            self.private_headers = true;
            self.syms = true;
        }
        if self.source {
            self.disassemble = true;
        }
        if self.ida_all {
            self.ida_header = true;
            self.ida_jump = true;
            self.ida_xrefs = true;
        }
        if self.ida_xrefs {
            self.ida_jump = true;
        }
    }
}

fn parse_hex_or_dec(s: &str) -> Result<u64, String> {
    let s = s.trim().replace('_', "");
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("'{s}' is not a valid hex number"))
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("'{s}' is not a valid hex number"))
    }
}
