pub mod samples {
    use iced_x86::{Instruction, code_asm::*};

    pub fn arxan_call() -> Vec<Instruction> {
        let mut asm = CodeAssembler::new(64).unwrap();
        asm.lea(rsp, qword_ptr(rsp - 8)).unwrap();
        asm.mov(qword_ptr(rsp), rbp).unwrap();
        asm.mov(rbp, 0x10000u64).unwrap();
        asm.xchg(qword_ptr(rsp), rbp).unwrap();
        asm.push(rbp).unwrap();
        asm.mov(rbp, 0x20000u64).unwrap();
        asm.xchg(qword_ptr(rsp), rbp).unwrap();
        asm.ret().unwrap();
        asm.take_instructions()
    }

    // dsr 1.03.1 @1425c4826
    pub fn arxan_cmov() -> Vec<Instruction> {
        let mut asm = CodeAssembler::new(64).unwrap();
        asm.lea(rsp, qword_ptr(rsp - 8)).unwrap();
        asm.mov(qword_ptr(rsp), rbp).unwrap();
        asm.mov(rbp, 0x10000u64).unwrap();
        asm.xchg(qword_ptr(rsp), rbp).unwrap();
        asm.mov(qword_ptr(rsp - 8), rcx).unwrap();
        asm.lea(rsp, qword_ptr(rsp - 8)).unwrap();
        asm.lea(rsp, qword_ptr(rsp - 8)).unwrap();
        asm.mov(qword_ptr(rsp), rdx).unwrap();
        asm.mov(rcx, qword_ptr(rsp + 0x10)).unwrap();
        asm.mov(rdx, 0x20000u64).unwrap();
        asm.cmovz(rcx, rdx).unwrap();
        asm.mov(qword_ptr(rsp + 0x10), rcx).unwrap();
        asm.lea(rsp, qword_ptr(rsp + 8)).unwrap();
        asm.mov(rdx, qword_ptr(rsp - 8)).unwrap();
        asm.mov(rcx, qword_ptr(rsp)).unwrap();
        asm.lea(rsp, qword_ptr(rsp + 8)).unwrap();
        asm.lea(rsp, qword_ptr(rsp + 8)).unwrap();
        asm.jmp(qword_ptr(rsp - 8)).unwrap();
        asm.take_instructions()
    }
}
