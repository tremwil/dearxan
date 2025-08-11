use iced_x86::Register;

use super::expr::Expr;

#[derive(Debug, Clone)]
pub struct Registers {
    gprs: [Expr; Self::GPR_COUNT],
    rip: Option<Expr>,
}

impl Registers {
    const GPR_COUNT: usize = Register::R15 as usize - Register::RAX as usize + 1;

    pub fn gpr64(&self, r: Register) -> &Expr {
        assert!(r.is_gpr64());
        &self.gprs[r as usize - Register::RAX as usize]
    }

    pub fn gpr64_mut(&mut self, r: Register) -> &mut Expr {
        assert!(r.is_gpr64());
        &mut self.gprs[r as usize - Register::RAX as usize]
    }

    pub fn rip(&self) -> &Option<Expr> {
        &self.rip
    }

    pub fn rip_mut(&mut self) -> &mut Option<Expr> {
        &mut self.rip
    }

    pub fn rsp(&self) -> &Expr {
        self.gpr64(Register::RSP)
    }

    pub fn rsp_mut(&mut self) -> &mut Expr {
        self.gpr64_mut(Register::RSP)
    }

    pub fn gprs_equal_except(
        &self,
        regs: &Self,
        exceptions: impl IntoIterator<Item = (Register, Expr)>,
    ) -> bool {
        let mut needs_check = [true; Self::GPR_COUNT];
        for (reg, expr) in exceptions {
            if self.gpr64(reg) != &expr {
                return false;
            }
            needs_check[reg as usize - Register::RAX as usize] = false;
        }
        self.gprs
            .iter()
            .zip(&regs.gprs)
            .zip(needs_check)
            .filter(|(_, needs_check)| *needs_check)
            .all(|((act, exp), _)| act == exp)
    }
}

impl Default for Registers {
    fn default() -> Self {
        let mut gprs = [Expr::Unknown; Self::GPR_COUNT];
        for i in 0..Self::GPR_COUNT {
            gprs[i] = Expr::InitRegister((Register::RAX as usize + i).try_into().unwrap())
        }
        Registers { gprs, rip: None }
    }
}
