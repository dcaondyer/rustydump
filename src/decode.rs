pub struct DecodedInstruction {
    pub ip: u64,
    pub len: u32,
    pub instruction: iced_x86::Instruction,
}

pub fn decode_section(bitness: u32, bytes: &[u8], rip: u64) -> Vec<DecodedInstruction> {
    Vec::new()
}
