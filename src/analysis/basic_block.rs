use crate::decode::InstIR;

#[derive(Debug)]
pub struct BasicBlock {
    pub id: usize,
    pub addr: u64,     // indirizzo del primo byte
    pub end_addr: u64, // indirizzo del primo byte DOPO il blocco
    pub instructions: Vec<InstIR>,
    pub successors: Vec<usize>,   // id dei blocchi successori
    pub predecessors: Vec<usize>, // id dei blocchi predecessori
}

impl BasicBlock {
    pub fn new(id: usize, addr: u64) -> Self {
        Self {
            id,
            addr,
            end_addr: addr,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    pub fn terminator(&self) -> Option<&InstIR> {
        self.instructions.last()
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}
