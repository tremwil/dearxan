use iced_x86::Register;

use super::util;

/// Struct holding the values of x64 general-purpose registers (RAX-R15).
#[derive(Default, Clone)]
pub struct Registers([Option<u64>; Self::GPR_COUNT]);

impl Registers {
    pub const GPR_COUNT: usize = 16;

    /// Create a [`Registers`] instance with initial values given by an iterator.
    ///
    /// Registers without an initial value are set to [`None`].
    pub fn new(values: impl IntoIterator<Item = (Register, u64)>) -> Self {
        let mut s = Self::default();
        for (reg, val) in values {
            s.write_gpr(reg, Some(val));
        }
        s
    }

    /// Get the value of the 64-bit general-purpose register `r` if it is known.
    ///
    /// # Panics
    /// If `r` is not a 64-bit general-purpose register (RAX-R15).
    #[inline]
    pub fn gpr64(&self, r: Register) -> Option<u64> {
        assert!(r.is_gpr64()); // This assertion will make the bounds check below go away
        self.0[r as usize - Register::RAX as usize]
    }

    /// Get a mutable reference to the 64-bit general-purpose register `r`.
    ///
    /// # Panics
    /// If `r` is not a 64-bit general-purpose register (RAX-R15).
    #[inline]
    pub fn gpr64_mut(&mut self, r: Register) -> &mut Option<u64> {
        assert!(r.is_gpr64()); // This assertion will make the bounds check below go away
        &mut self.0[r as usize - Register::RAX as usize]
    }

    /// Read zero-extended general-purpose register. Value is assumed to be unsigned.
    ///
    /// # Panics
    /// If `r` is a not a general-purpose register.
    pub fn read_gpr(&self, r: Register) -> Option<u64> {
        Some(util::reinterpret_unsigned(
            self.gpr64(r.full_register())?,
            r.size(),
        ))
    }

    /// Write a zero-exetended general-purpose register. Value is assumed to be unsigned.
    ///
    /// # Panics
    /// If `r` is a not a general-purpose register.
    pub fn write_gpr(&mut self, r: Register, val: Option<u64>) {
        match (self.gpr64_mut(r.full_register()), val, r.size()) {
            // 64-bit write
            (old, Some(new), 8) => *old = Some(new),
            // 32-bit write (clears upper bits)
            (old, Some(new), 4) => *old = Some(new & (u32::MAX as u64)),
            // 16 or 8-bit write (doesn't affect upper bits)
            (Some(old), Some(new), 2) => *old = (*old & !0xFFFF) | (new & 0xFFFF),
            (Some(old), Some(new), 1) => *old = (*old & !0xFF) | (new & 0xFF),
            // Writing None (clears known register value)
            (old, None, _) => *old = None,
            // Writing to None with non-clobbering size (full register still unknown)
            (None, _, _) => (),
            _ => unreachable!(),
        }
    }
}

macro_rules! register_impl {
    ($reg:ident, $name:ident, $name_mut:ident) => {
        #[inline]
        pub fn $name(&self) -> Option<u64> {
            self.gpr64(Register::$reg)
        }
        #[inline]
        pub fn $name_mut(&mut self) -> &mut Option<u64> {
            self.gpr64_mut(Register::$reg)
        }
    };
}

#[allow(dead_code)]
impl Registers {
    register_impl!(RAX, rax, rax_mut);
    register_impl!(RCX, rcx, rcx_mut);
    register_impl!(RDX, rdx, rdx_mut);
    register_impl!(RBX, rbx, rbx_mut);
    register_impl!(RSP, rsp, rsp_mut);
    register_impl!(RBP, rbp, rbp_mut);
    register_impl!(RSI, rsi, rsi_mut);
    register_impl!(RDI, rdi, rdi_mut);
    register_impl!(R8, r8, r8_mut);
    register_impl!(R9, r9, r9_mut);
    register_impl!(R10, r10, r10_mut);
    register_impl!(R11, r11, r11_mut);
    register_impl!(R12, r12, r12_mut);
    register_impl!(R13, r13, r13_mut);
    register_impl!(R14, r14, r14_mut);
    register_impl!(R15, r15, r15_mut);
}

impl std::fmt::Debug for Registers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("Registers");
        for (i, val) in self.0.iter().enumerate().filter(|(_, r)| r.is_some()) {
            ds.field(&format!("{:?}", Register::RAX + i as u32), &val.unwrap());
        }
        ds.finish()?;
        Ok(())
    }
}
