use crate::decode::BackendKind;
use crate::demangle::DemangleStyle;
use clap::{ArgGroup, Parser};
use std::path::PathBuf;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

/// Corrisponde ai flag -M di objdump per il dialetto assembly
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

/// Tutte le opzioni, una per flag come il vero objdump
#[derive(Parser, Debug)]
#[command(
     name    = "rustydump",
     version = {VERSION},
     about   = "Display information from object files (objdump clone)",
     long_about = None,
     // Almeno una action richiesta, come nel vero objdump
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
    // ── File di input ─────────────────────────────────────────────────────────
    #[arg(
        value_name = "FILE",
        required = true,
        help = "Object file(s) to examine"
    )]
    pub files: Vec<PathBuf>,

    // ── Azioni ───────────────────────────────────────────────────────────────
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

    // ── Modificatori ─────────────────────────────────────────────────────────
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
        long = "ida-header",
        help = "Print an IDA Pro-style header before each section and function listing"
    )]
    pub ida_header: bool,

    #[arg(
        long = "cfg",
        help = "Build and print the Control Flow Graph of executable sections",
        group = "action"
    )]
    pub build_cfg: bool,

    #[arg(
        long = "cfg-dot",
        value_name = "FILE",
        help = "Export CFG as Graphviz DOT file (e.g. --cfg-dot=out.dot)",
        group = "action"
    )]
    pub cfg_dot: Option<PathBuf>,

    #[arg(
        long = "backend",
        value_name = "BACKEND",
        default_value = "iced",
        help = "Decoder backend to use for CFG construction"
    )]
    pub backend: BackendKind,
}

impl Config {
    /// Espande -x in tutti i flag che implica, come fa il vero objdump.
    /// Va chiamata dopo il parsing di clap.
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
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

// ── Value parser per --adjust-vma (accetta sia hex che decimale) ──────────────

fn parse_hex_or_dec(s: &str) -> Result<u64, String> {
    let s = s.trim().replace('_', "");
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("'{s}' is not a valid hex number"))
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("'{s}' is not a valid hex number"))
    }
}
