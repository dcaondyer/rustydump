use std::path::PathBuf;
use std::process;

pub enum InstructionFormat {
    Intel,
    Gas,
    Masm,
    Nasm,
}

const DEFAULT_CODE_RIP: u64 = 0x0000_7FFA_C46A_CDA4;
const DEFAULT_INSTR_FORMAT: InstructionFormat = InstructionFormat::Intel;

pub struct Config {
    pub code_bitness: u32,
    pub file_path: PathBuf,
    pub code_rip: u64,
    pub instr_format: InstructionFormat,
}

impl Config {
    pub fn build(args: &[String]) -> Result<Config, &'static str> {
        if args.len() < 2 {
            return Err("Not enough arguments!");
        }

        if args[1].to_lowercase() == "help" {
            print_menu();
            process::exit(0);
        }

        if args.len() < 3 {
            return Err("Not enough arguments!");
        }

        let code_bitness = parse_bitness(&args[1]).unwrap_or_else(|_| {
            print_menu();
            process::exit(0);
        });

        let file_path = PathBuf::from(&args[2]);

        let code_rip = if args.len() > 3 {
            parse_rip(&args[3]).unwrap_or_else(|_| {
                print_menu();
                process::exit(0);
            })
        } else {
            DEFAULT_CODE_RIP
        };

        let instr_format = if args.len() > 4 {
            parse_instr_format(&args[3]).unwrap_or_else(|_| {
                print_menu();
                process::exit(0);
            })
        } else {
            DEFAULT_INSTR_FORMAT
        };

        Ok(Config {
            code_bitness,
            file_path,
            code_rip,
            instr_format,
        })
    }
}

fn parse_bitness(s: &str) -> Result<u32, &'static str> {
    match s.trim().parse::<u32>() {
        Ok(n) if n == 16 || n == 32 || n == 64 => Ok(n),
        Ok(_) => Err("The code bitness value must be one of 16, 32, or 64"),
        Err(_) => Err("Invalid bitness value"),
    }
}

fn parse_rip(s: &str) -> Result<u64, &'static str> {
    let s = s.trim().replace('_', "").to_lowercase();
    let hex = s.strip_prefix("0x").unwrap_or(&s);
    u64::from_str_radix(hex, 16).map_err(|_| "Invalid code_rip hex value")
}

fn parse_instr_format(s: &str) -> Result<InstructionFormat, &'static str> {
    let s = s.trim().to_lowercase();
    match s.as_str() {
        "intel" => Ok(InstructionFormat::Intel),
        "gas" => Ok(InstructionFormat::Gas),
        "masm" => Ok(InstructionFormat::Masm),
        "nasm" => Ok(InstructionFormat::Nasm),
        _ => Err("Invalid instruction format"),
    }
}

pub fn print_menu() {
    println!("rustydump — a clone of objdump based on iced-x86 and goblin");
    println!();
    println!("Typical command:");
    println!("  rustydump [16|32|64] <file_path> [code_rip] [instr_format]");
    println!("  rustydump help");
    println!();
    println!("Arguments:");
    println!("  16|32|64            Binary architecture");
    println!("  file_path           PE or ELF file path");
    println!("  code_rip            RIP/EIP register value in hex format (optional)");
    println!("  instr_format        instruction format [Intel, Gas, Masm, Nasm] (optional)");
    println!();
    println!("Examples:");
    println!("  rustydump 64 ./my_binary");
    println!("  rustydump 32 ./app.exe 0x00401000");
    println!();
}
