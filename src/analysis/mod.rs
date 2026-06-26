mod basic_block;
mod cfg;

use crate::analysis::cfg::Cfg;
use crate::decode::iced::IcedBackend;
use crate::decode::zydis::ZydisBackend;
use crate::decode::{BackendKind, DecoderBackend};
use crate::formats::ExecutableSection;
use std::fs;
use std::path::Path;

pub fn construct_cfg(
    section: &ExecutableSection,
    bitness: u32,
    backend: BackendKind,
    dot_output: Option<&Path>,
) -> Result<Cfg, Box<dyn std::error::Error>> {
    // Dispatch concreto tramite enum — nessun problema di tipo
    let instructions = match backend {
        BackendKind::Iced => {
            IcedBackend::new().decode_section(bitness, &section.data, section.virtual_address)
        }
        BackendKind::Zydis => {
            ZydisBackend::new().decode_section(bitness, &section.data, section.virtual_address)
        }
    };

    let cfg = Cfg::build(instructions);
    cfg.print();

    let loops = cfg.back_edges();
    println!("{} loop(s) found", loops.len());

    let dead = cfg.dead_blocks();
    println!("{} block(s) of dead code", dead.len());

    // Export DOT se richiesto
    if let Some(path) = dot_output {
        let dot = cfg.to_dot(&section.name);
        fs::write(path, dot)?;
        println!("CFG exported to {}", path.display());
    }

    Ok(cfg)
}
