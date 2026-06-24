use clap::Parser;
use rustydump::config::Config;
use rustydump::process_file;
use std::process;

fn main() {
    let mut config = Config::parse();
    config.normalize();

    for file in &config.files {
        if let Err(e) = process_file(file, &config) {
            eprintln!("rustydump: {}: {e}", file.display());
            eprintln!();
            process::exit(1);
        }
    }
}
