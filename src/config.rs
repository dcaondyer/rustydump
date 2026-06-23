use std::path::PathBuf;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

/// Corrisponde ai flag -M di objdump per il dialetto assembly
#[derive(Debug, Clone, Copy, Default)]
pub enum InstructionFormat {
    #[default]
    Intel,
    Gas, // AT&T syntax (default di objdump GNU)
    Masm,
    Nasm,
}

/// Tutte le opzioni, una per flag come il vero objdump
#[derive(Debug, Default)]
pub struct Config {
    // Azioni (almeno una richiesta, come in objdump)
    pub disassemble: bool,     // -d / --disassemble
    pub disassemble_all: bool, // -D / --disassemble-all
    pub file_headers: bool,    // -f / --file-headers
    pub section_headers: bool, // -h / --section-headers / --headers
    pub all_headers: bool,     // -x / --all-headers
    pub full_contents: bool,   // -s / --full-contents
    pub syms: bool,            // -t / --syms
    pub dynamic_syms: bool,    // -T / --dynamic-syms
    pub private_headers: bool, // -p / --private-headers

    // Modificatori
    pub demangle: bool,                  // -C / --demangle
    pub source: bool,                    // -S / --source
    pub adjust_vma: u64,                 // --adjust-vma=<offset>
    pub section_filter: Option<String>,  // -j <section> / --section=<name>
    pub instr_format: InstructionFormat, // -M intel / -M att / ecc.

    // Input
    pub files: Vec<PathBuf>,
}

impl Config {
    pub fn build(args: &[String]) -> Result<Config, String> {
        let mut cfg = Config::default();
        let mut i = 1; // salta argv[0]

        if args.len() < 2 {
            return Err("No file specified.".into());
        }

        while i < args.len() {
            let arg = &args[i];

            match arg.as_str() {
                // ── Aiuto / versione ───────────────────────────────────────
                "-H" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    println!("rustydump {} (iced-x86 + goblin)", VERSION);
                    std::process::exit(0);
                }

                // ── Azioni ─────────────────────────────────────────────────
                "-d" | "--disassemble" => cfg.disassemble = true,
                "-D" | "--disassemble-all" => cfg.disassemble_all = true,
                "-f" | "--file-headers" => cfg.file_headers = true,
                "-s" | "--full-contents" => cfg.full_contents = true,
                "-t" | "--syms" => cfg.syms = true,
                "-T" | "--dynamic-syms" => cfg.dynamic_syms = true,
                "-p" | "--private-headers" => cfg.private_headers = true,
                "-C" | "--demangle" => cfg.demangle = true,
                "-S" | "--source" => {
                    cfg.source = true;
                    cfg.disassemble = true;
                }

                // -h / -x espandono entrambi all_headers / section_headers
                "-h" | "--section-headers" | "--headers" => cfg.section_headers = true,
                "-x" | "--all-headers" => {
                    cfg.all_headers = true;
                    cfg.file_headers = true;
                    cfg.section_headers = true;
                    cfg.private_headers = true;
                    cfg.syms = true;
                }

                // ── Modificatori con valore ────────────────────────────────
                "-j" | "--section" => {
                    i += 1;
                    cfg.section_filter = Some(next_arg(args, i, "-j")?);
                }
                "-M" | "--disassembler-options" => {
                    i += 1;
                    let opt = next_arg(args, i, "-M")?;
                    cfg.instr_format = parse_m_flag(&opt)?;
                }
                "--adjust-vma" => {
                    i += 1;
                    let val = next_arg(args, i, "--adjust-vma")?;
                    cfg.adjust_vma = parse_hex_or_dec(&val)
                        .map_err(|_| format!("--adjust-vma: value not valid '{val}'"))?;
                }

                // ── Forma --flag=valore ────────────────────────────────────
                s if s.starts_with("--section=") => {
                    cfg.section_filter = Some(s["--section=".len()..].to_string());
                }
                s if s.starts_with("-M") && s.len() > 2 => {
                    cfg.instr_format = parse_m_flag(&s[2..])?;
                }
                s if s.starts_with("--adjust-vma=") => {
                    let val = &s["--adjust-vma=".len()..];
                    cfg.adjust_vma = parse_hex_or_dec(val)
                        .map_err(|_| format!("--adjust-vma: value not valid '{val}'"))?;
                }
                s if s.starts_with("--disassembler-options=") => {
                    let opt = &s["--disassembler-options=".len()..];
                    cfg.instr_format = parse_m_flag(opt)?;
                }

                // ── Raggruppamento flag corti (-dhs, -dM intel) ────────────
                s if s.starts_with('-') && !s.starts_with("--") && s.len() > 2 => {
                    // Espandi "-dhf" in "-d", "-h", "-f"
                    let expanded: Vec<String> = s[1..].chars().map(|c| format!("-{c}")).collect();
                    // Reinserisci all'inizio della coda (ricorsione piatta)
                    let mut new_args: Vec<String> = args[..i].to_vec();
                    new_args.extend(expanded);
                    new_args.extend_from_slice(&args[i + 1..]);
                    return Config::build(&new_args);
                }

                // ── File di input ──────────────────────────────────────────
                s => cfg.files.push(PathBuf::from(s)),
            }

            i += 1;
        }

        if cfg.files.is_empty() {
            return Err("No file specified".into());
        }

        if !cfg.has_action() {
            return Err(
                "At least one of -a -d -D -f -h -p -s -S -t -T -V -x must be specified".into(),
            );
        }

        Ok(cfg)
    }

    fn has_action(&self) -> bool {
        self.disassemble
            || self.disassemble_all
            || self.file_headers
            || self.section_headers
            || self.all_headers
            || self.full_contents
            || self.syms
            || self.dynamic_syms
            || self.private_headers
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn next_arg(args: &[String], i: usize, flag: &str) -> Result<String, String> {
    args.get(i)
        .cloned()
        .ok_or_else(|| format!("'{flag}' requires an argument"))
}

fn parse_m_flag(opt: &str) -> Result<InstructionFormat, String> {
    match opt.to_lowercase().as_str() {
        "intel" => Ok(InstructionFormat::Intel),
        "att" | "gas" => Ok(InstructionFormat::Gas),
        "masm" => Ok(InstructionFormat::Masm),
        "nasm" => Ok(InstructionFormat::Nasm),
        other => Err(format!(
            "-M: unknown option '{other}'. Values: intel, att, masm, nasm"
        )),
    }
}

fn parse_hex_or_dec(s: &str) -> Result<u64, ()> {
    let s = s.trim().replace('_', "");
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        s.parse::<u64>().map_err(|_| ())
    }
}

pub fn print_help() {
    println!("Usage: rustydump <options> <file...>");
    println!();
    println!("Print information from object files");
    println!("At least one of these options is required:");
    println!();
    println!(" -d, --disassemble        Disassembly executable sections");
    println!(" -D, --disassemble-all    Disassembly all sections");
    println!(" -f, --file-headers       Print file header");
    println!(" -h, --section-headers    Print sections headers");
    println!(" -p, --private-headers    Print specific format headers");
    println!(" -s, --full-contents      Print hex content of all sections");
    println!(" -t, --syms               Print symbol table");
    println!(" -T, --dynamic-syms       Print dynamic symbol table");
    println!(" -x, --all-headers        Equals to -d -f -h -p -t combined");
    println!();
    println!("Modifiers:");
    println!(" -j, --section=<nome>     Limits output to specified section");
    println!(" -M, --disassembler-options=<opt>");
    println!("                          intel (default) | att | masm | nasm");
    println!(" -C, --demangle           Decode C++ symbols names");
    println!(" -S, --source             Print source code mixed with disassembly");
    println!("     --adjust-vma=<off>   Ad offset to sections addresses");
    println!();
    println!(" -H, --help               Print these message");
    println!(" -V, --version            Print version");
    println!();
    println!("Examples:");
    println!("  rustydump -d ./binary");
    println!("  rustydump -d -M intel ./binary");
    println!("  rustydump -d -j .text ./binary");
    println!("  rustydump -f -h ./binary");
    println!("  rustydump -x ./binary");
}
