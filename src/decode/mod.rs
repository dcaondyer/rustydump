pub mod iced;
pub mod zydis;

#[derive(Clone, Debug)]
pub struct Reg {
    pub name: String,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub struct Mem {
    pub base: Option<Reg>,
    pub index: Option<Reg>,
    pub scale: u32,
    pub disp: u64,
}

#[derive(Clone, Debug)]
pub enum Operand {
    Reg(Reg),
    Imm(u64),
    Mem(Mem),
}

#[derive(Debug)]
pub enum Flow {
    Next,
    Jump(u64),
    Conditional(u64, u64),
    Call(u64),
    Return,
}

#[derive(Debug)]
pub enum OpKind {
    Mov,
    Load,
    Store,
    Add,
    Sub,
    Mul,
    Div,
    Call,
    Ret,
    Jmp,
    Cjmp,
}

#[derive(Debug)]
pub struct InstIR {
    pub addr: u64,
    pub size: usize,

    pub op: OpKind,

    pub dst: Option<Operand>,
    pub src: Vec<Operand>,

    pub flow: Flow,
}

pub trait DecoderBackend {
    fn decode_section(&self, bitness: u32, bytes: &[u8], rip: u64) -> Vec<InstIR>;
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum BackendKind {
    #[default]
    Iced,
    Zydis,
}
