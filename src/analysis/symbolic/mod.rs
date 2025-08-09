use fxhash::FxHashMap;
use iced_x86::{ConditionCode, Instruction, Mnemonic, OpKind, Register};

use crate::analysis::ImageView;

type FxIndexSet<T> = indexmap::IndexSet<T, fxhash::FxBuildHasher>;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ExprId(usize);

fn invert_cond(cond: ConditionCode) -> ConditionCode {
    match cond {
        ConditionCode::None => ConditionCode::None,
        _ if (cond as usize).is_multiple_of(2) => (cond as usize - 1).try_into().unwrap(),
        _ => (cond as usize + 1).try_into().unwrap(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Expr {
    Unknown,
    Constant(u64),
    InitRegister(Register),
    /// Expression stored in the expression heap.
    Boxed(ExprId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BoxedExpr {
    InitMemory(Expr),
    // Unique and sorted exprs, no unknowns
    Linear(Vec<(Expr, u64)>),
    Ternary {
        // Restricted to *even* codes
        cond: ConditionCode,
        if_true: Expr,
        if_false: Expr,
    },
}

#[derive(Default, Debug, Clone)]
struct ExprHeap {
    /// All heap-stored expresions are canonicalized.
    store: FxIndexSet<BoxedExpr>,
    linear_scratch_buf: Vec<(Expr, u64)>,
}

impl ExprHeap {
    fn init_memory(&mut self, expr: Expr) -> ExprId {
        ExprId(self.store.insert_full(BoxedExpr::InitMemory(expr)).0)
    }

    fn ternary(&mut self, mut cond: ConditionCode, mut if_true: Expr, mut if_false: Expr) -> Expr {
        if if_true == if_false {
            return if_true;
        }
        if !(cond as usize).is_multiple_of(2) {
            cond = (cond as usize + 1).try_into().unwrap();
            std::mem::swap(&mut if_true, &mut if_false);
        }
        let boxed = BoxedExpr::Ternary {
            cond,
            if_true,
            if_false,
        };
        Expr::Boxed(ExprId(self.store.insert_full(boxed).0))
    }

    fn linear(&mut self, terms: impl IntoIterator<Item = (Expr, u64)>) -> Expr {
        let mut terms = terms.into_iter().peekable();

        if terms.size_hint().1 == Some(0) {
            return Expr::Constant(0);
        }

        let mut acc_constant = 0;
        self.linear_scratch_buf.clear();

        todo!()
    }
}

#[derive(Default, Debug, Clone)]
struct Memory {
    contents: FxHashMap<Expr, Expr>,
}

#[derive(Debug, Clone)]
struct Registers {
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

struct SymbolicState {
    heap: ExprHeap,
    memory: FxHashMap<Expr, Expr>,
    unk_mem_write: bool,
}

impl SymbolicState {}
