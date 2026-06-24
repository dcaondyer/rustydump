use crate::decode::{DecoderBackend, Flow, InstIR, Mem, OpKind, Operand, Reg};
use iced_x86::{Decoder, DecoderOptions, OpKind as IcedOpKind};
use iced_x86::{FlowControl, Instruction, Mnemonic, Register};

pub struct IcedBackend {}

impl IcedBackend {
    pub fn new() -> impl DecoderBackend {
        IcedBackend {}
    }

    fn reg_size(reg: Register) -> usize {
        match reg.size() {
            1 | 2 | 4 | 8 | 16 | 32 | 64 => reg.size() as usize,
            _ => 0,
        }
    }

    fn convert_reg(reg: Register) -> Reg {
        Reg {
            name: format!("{reg:?}").to_lowercase(),
            size: IcedBackend::reg_size(reg),
        }
    }

    fn convert_mem(instr: &Instruction) -> Mem {
        Mem {
            base: match instr.memory_base() {
                Register::None => None,
                r => Some(IcedBackend::convert_reg(r)),
            },

            index: match instr.memory_index() {
                Register::None => None,
                r => Some(IcedBackend::convert_reg(r)),
            },

            scale: instr.memory_index_scale(),

            disp: instr.memory_displacement64(),
        }
    }

    fn operand_from(instr: &Instruction, op_idx: u32) -> Option<Operand> {
        match instr.op_kind(op_idx) {
            IcedOpKind::Register => Some(Operand::Reg(IcedBackend::convert_reg(
                instr.op_register(op_idx),
            ))),

            IcedOpKind::NearBranch16 | IcedOpKind::NearBranch32 | IcedOpKind::NearBranch64 => {
                Some(Operand::Imm(instr.near_branch_target()))
            }

            IcedOpKind::Immediate8
            | IcedOpKind::Immediate16
            | IcedOpKind::Immediate32
            | IcedOpKind::Immediate64 => Some(Operand::Imm(instr.immediate64())),

            IcedOpKind::Memory => Some(Operand::Mem(IcedBackend::convert_mem(instr))),

            _ => None,
        }
    }

    fn convert_flow(instr: &Instruction) -> (Flow, Option<OpKind>) {
        match instr.flow_control() {
            FlowControl::Next => (Flow::Next, None),

            FlowControl::UnconditionalBranch => (Flow::Jump(instr.near_branch_target()), None),

            FlowControl::ConditionalBranch => {
                let next = instr.ip() + instr.len() as u64;

                (
                    Flow::Conditional(instr.near_branch_target(), next),
                    Some(OpKind::Cjmp),
                )
            }

            FlowControl::Call => (Flow::Call(instr.near_branch_target()), None),

            FlowControl::Return => (Flow::Return, None),

            _ => (Flow::Next, None),
        }
    }

    fn convert_opcode(instr: &Instruction) -> OpKind {
        match instr.mnemonic() {
            Mnemonic::Mov => OpKind::Mov,

            Mnemonic::Add => OpKind::Add,

            Mnemonic::Sub => OpKind::Sub,

            Mnemonic::Imul | Mnemonic::Mul => OpKind::Mul,

            Mnemonic::Div | Mnemonic::Idiv => OpKind::Div,

            Mnemonic::Call => OpKind::Call,

            Mnemonic::Ret => OpKind::Ret,

            Mnemonic::Jmp => OpKind::Jmp,

            _ => OpKind::Mov,
        }
    }

    fn lift_instruction(instr: &Instruction) -> InstIR {
        let mut ops = Vec::new();

        for i in 0..instr.op_count() {
            if let Some(op) = IcedBackend::operand_from(instr, i) {
                ops.push(op);
            }
        }

        let dst = ops.first().cloned();

        let src = ops.iter().skip(1).cloned().collect();

        let (flow, op) = match IcedBackend::convert_flow(instr) {
            (flow, Some(kind)) => (flow, kind),
            (flow, None) => (flow, IcedBackend::convert_opcode(instr)),
        };

        InstIR {
            addr: instr.ip(),
            size: instr.len(),
            op,
            dst,
            src,
            flow,
        }
    }

    pub fn decode_section_iced(bitness: u32, bytes: &[u8], rip: u64) -> Vec<InstIR> {
        let mut decoder = Decoder::with_ip(bitness, bytes, rip, DecoderOptions::NONE);

        let mut out = Vec::new();

        for instr in &mut decoder {
            out.push(IcedBackend::lift_instruction(&instr));
        }

        out
    }
}

impl DecoderBackend for IcedBackend {
    fn decode_section(&self, bitness: u32, bytes: &[u8], rip: u64) -> Vec<InstIR> {
        IcedBackend::decode_section_iced(bitness, bytes, rip)
    }
}
