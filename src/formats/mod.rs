pub mod elf;
pub mod macho;
pub mod pe;

use std::error::Error;

pub enum ExecutableFormat {
    Elf,
    PE,
    MachO,
}

/// Rappresenta una sezione eseguibile estratta dal binario
pub struct ExecutableSection {
    pub name: String,
    pub data: Vec<u8>,
    pub virtual_address: u64,
    pub offset: u64,
    pub size: u64,
    pub section_flags: Option<u64>,
    pub object_format: Option<ExecutableFormat>,
}

pub trait BinaryFormat {
    fn parse(bytes: &[u8]) -> Result<Vec<ExecutableSection>, Box<dyn Error>>;
    fn format_name() -> &'static str;
}
