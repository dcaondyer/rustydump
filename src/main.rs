use rustydump::config::{print_help, Config};
use rustydump::process_file;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = Config::build(&args).unwrap_or_else(|err| {
        eprintln!("rustydump: {err}");
        eprintln!("Try 'rustydump -H' for help");
        eprintln!();
        print_help();
        process::exit(0);
    });

    for file in &config.files {
        if let Err(e) = process_file(file, &config) {
            eprintln!("rustydump: {}: {e}", file.display());
            eprintln!();
            process::exit(1);
        }
    }
}
