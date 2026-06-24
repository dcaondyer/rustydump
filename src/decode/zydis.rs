use crate::decode::{DecoderBackend, Flow, InstIR, Mem, OpKind, Operand, Reg};
use zydis::{MachineMode, Register, StackWidth, VisibleOperands};

pub struct ZydisBackend {}

impl ZydisBackend {
    pub fn new() -> impl DecoderBackend {
        ZydisBackend {}
    }

    fn zydis_mode(bitness: u32) -> (MachineMode, StackWidth) {
        match bitness {
            16 => (MachineMode::REAL_16, StackWidth::_16),
            32 => (MachineMode::LEGACY_32, StackWidth::_32),
            64 => (MachineMode::LONG_64, StackWidth::_64),
            _ => panic!("Unsupported bitness: {}", bitness),
        }
    }

    fn reg_size(reg: Register, mode: MachineMode) -> usize {
        match reg.width(mode) {
            1 | 2 | 4 | 8 | 16 | 32 | 64 => reg.width(mode) as usize,
            _ => 0,
        }
    }

    fn convert_reg(reg: Register, mode: MachineMode) -> Reg {
        Reg {
            name: format!("{reg:?}").to_lowercase(),
            size: ZydisBackend::reg_size(reg, mode),
        }
    }

    fn convert_mem(mem: &zydis::ffi::MemoryInfo, mode: MachineMode) -> Mem {
        Mem {
            base: match mem.base {
                Register::NONE => None,
                r => Some(ZydisBackend::convert_reg(r, mode)),
            },
            index: match mem.index {
                Register::NONE => None,
                r => Some(ZydisBackend::convert_reg(r, mode)),
            },
            scale: mem.scale as u32,
            disp: mem.disp.displacement as u64,
        }
    }
    fn operand_from(op: &zydis::ffi::DecodedOperand, mode: MachineMode) -> Option<Operand> {
        use zydis::ffi::DecodedOperandKind;
        match &op.kind {
            DecodedOperandKind::Reg(reg) => {
                Some(Operand::Reg(ZydisBackend::convert_reg(*reg, mode)))
            }
            DecodedOperandKind::Imm(imm) => Some(Operand::Imm(imm.value as u64)),
            DecodedOperandKind::Mem(mem) => {
                Some(Operand::Mem(ZydisBackend::convert_mem(mem, mode)))
            }
            _ => None,
        }
    }

    fn is_conditional_jump(mnemonic: zydis::Mnemonic) -> bool {
        use zydis::Mnemonic::*;
        match mnemonic {
            JB | JBE | JCXZ | JECXZ | JRCXZ | JL | JLE | JNO | JNP | JNS | JO | JP | JS => true,
            _ => false,
        }
    }

    fn branch_target(ip: u64, len: usize, operands: &[zydis::ffi::DecodedOperand]) -> Option<u64> {
        use zydis::ffi::DecodedOperandKind;
        let op = operands.first()?;
        match &op.kind {
            DecodedOperandKind::Imm(imm) => {
                Some((ip as i64 + len as i64 + imm.value as i64) as u64)
            }
            _ => None,
        }
    }

    fn convert_flow(
        instr: &zydis::ffi::DecodedInstruction,
        operands: &[zydis::ffi::DecodedOperand],
        ip: u64,
    ) -> (Flow, Option<OpKind>) {
        use zydis::Mnemonic::*;
        let next = ip + instr.length as u64;
        let len = instr.length as usize;

        match instr.mnemonic {
            CALL => {
                let target = ZydisBackend::branch_target(ip, len, operands).unwrap_or(0);
                (Flow::Call(target), Some(OpKind::Call))
            }
            RET => (Flow::Return, Some(OpKind::Ret)),
            JMP => {
                let target = ZydisBackend::branch_target(ip, len, operands).unwrap_or(0);
                (Flow::Jump(target), Some(OpKind::Jmp))
            }
            m if ZydisBackend::is_conditional_jump(m) => {
                let target = ZydisBackend::branch_target(ip, len, operands).unwrap_or(0);
                (Flow::Conditional(target, next), Some(OpKind::Cjmp))
            }
            _ => (Flow::Next, None),
        }
    }

    fn convert_opcode(instr: &zydis::ffi::DecodedInstruction) -> OpKind {
        use zydis::Mnemonic::*;
        match instr.mnemonic {
            MOV => OpKind::Mov,
            ADD => OpKind::Add,
            SUB => OpKind::Sub,
            MUL | IMUL => OpKind::Mul,
            DIV | IDIV => OpKind::Div,
            CALL => OpKind::Call,
            RET => OpKind::Ret,
            JMP => OpKind::Jmp,
            _ => OpKind::Mov,
        }
    }

    fn lift_instruction(
        instr: &zydis::ffi::DecodedInstruction,
        operands: &[zydis::ffi::DecodedOperand],
        ip: u64,
        mode: MachineMode,
    ) -> InstIR {
        let ops: Vec<Operand> = operands
            .iter()
            .filter_map(|op| ZydisBackend::operand_from(op, mode))
            .collect();

        let dst = ops.first().cloned();
        let src = ops.into_iter().skip(1).collect();
        let (flow, override_op) = ZydisBackend::convert_flow(instr, operands, ip);

        InstIR {
            addr: ip,
            size: instr.length as usize,
            op: override_op.unwrap_or_else(|| ZydisBackend::convert_opcode(instr)),
            dst,
            src,
            flow,
        }
    }

    pub fn decode_section_zydis(bitness: u32, bytes: &[u8], rip: u64) -> Vec<InstIR> {
        let (mode, width) = ZydisBackend::zydis_mode(bitness);
        let decoder = zydis::Decoder::new(mode, width).expect("Failed to create decoder");

        decoder
            .decode_all::<VisibleOperands>(bytes, rip)
            .filter_map(|res| res.ok())
            .map(|(ip, _raw_bytes, insn)| {
                // VisibleOperands implementa Deref<Target=[DecodedOperand]>
                // quindi &*insn dà direttamente la slice degli operandi visibili
                ZydisBackend::lift_instruction(&insn, &insn.operands(), ip, mode)
            })
            .collect()
    }
}

impl DecoderBackend for ZydisBackend {
    fn decode_section(&self, bitness: u32, bytes: &[u8], rip: u64) -> Vec<InstIR> {
        ZydisBackend::decode_section_zydis(bitness, bytes, rip)
    }
}
