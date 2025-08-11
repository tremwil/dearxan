type FxIndexSet<T> = indexmap::IndexSet<T, fxhash::FxBuildHasher>;

use iced_x86::{ConditionCode, Register};

use crate::analysis::util;

/// Unique identifier to a [`BoxedExpr`] symbolic expression stored in an [`ExprHeap`].
///
/// Has the important property that `a == b` if and only if `Expr::Boxed(a) == Expr::Boxed(b)`.
/// This significantly speeds up expression equality checks.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExprId(usize);

/// A symbolic expression for a 64-bit value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Expr {
    /// Unknown value.
    Unknown,
    /// Known numeric constant.
    Constant(u64),
    /// Initial value of a register when symbolic execution began.
    InitRegister(Register),
    /// Expression stored in the expression heap.
    Boxed(ExprId),
}

/// A compound/recursive symbolic expression for a 64-bit value.
///
/// Due to this recursiveness, it must created in an [`ExprHeap`] where it is assigned a unique
/// [`ExprId`].
///
/// Every boxed expression has a *canonical form*.
///
/// For canonicalized boxed expressions `expr1 == expr2` if and only if they are semantically
/// equivalent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BoxedExpr {
    /// Initial value of the memory relocation pointed to by the inner expression.
    InitMemory(Expr),
    /// Affine linear combination of expressions.
    ///
    /// In canonicalized form:
    /// - Containts at least one expr, and not with a coef. of 1 and constant of zero
    /// - Contains only unique and sorted exprs, with no unknowns, constants or other linear terms
    Linear {
        terms: Vec<(Expr, u64)>,
        constant: u64,
    },
    /// A conditional expression where one of two possible expressions may hold depending on the
    /// value of a condition.
    ///
    /// In canonicalized form:
    /// - `cond as usize` is an even number
    /// - `if_true` is not semantically equal to `is_false`
    Ternary {
        cond: ConditionCode,
        if_true: Expr,
        if_false: Expr,
    },
}

/// Storage for [`BoxedExpr`] expressions.
///
/// Boxed expressions are uniquely cached, so that each semantically equal expression shares the
/// same [`ExprId`]. This makes comparing expressions fast.
#[derive(Default, Debug, Clone)]
pub struct ExprHeap {
    /// Expressions are stored in a [`FxIndexSet`] for O(1) matching when creating a new boxed
    /// expression, and the ability to get an expression by its [`ExprId`] in O(1) time too.
    store: FxIndexSet<BoxedExpr>,
    /// Scratch buffer used to avoid reallocations when unpacking [`BoxedExpr::Linear`] terms.
    linear_scratch_buf: Vec<(Expr, u64)>,
}

impl ExprHeap {
    /// Creates an empty [`ExprHeap`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates an empty [`ExprHeap`] with initial capacity for `capacity` expressions.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            store: FxIndexSet::with_capacity_and_hasher(capacity, Default::default()),
            linear_scratch_buf: Vec::with_capacity(capacity),
        }
    }

    /// Clear the expression heap.
    ///
    /// This invalides all [`ExprId`] values obtained from it.
    pub fn clear(&mut self) {
        self.store.clear();
        self.linear_scratch_buf.clear();
    }

    /// Get a reference to a [`BoxedExpr`] created in this heap from its unique ID.
    pub fn get(&self, id: ExprId) -> Option<&BoxedExpr> {
        self.store.get_index(id.0)
    }

    /// Check if the given expression (created by this heap) contains [`BoxedExpr::Ternary`].
    pub fn has_ternary(&self, expr: &Expr) -> bool {
        let Expr::Boxed(id) = expr
        else {
            return false;
        };
        match self.get(*id).unwrap() {
            BoxedExpr::Ternary { .. } => true,
            BoxedExpr::InitMemory(inner) => self.has_ternary(inner),
            BoxedExpr::Linear { terms, .. } => terms.iter().any(|(t, _)| self.has_ternary(t)),
        }
    }

    /// Return the unique expression ID for a `BoxedExpr::InitMemory(expr)`.
    pub fn init_memory(&mut self, expr: Expr) -> ExprId {
        ExprId(self.store.insert_full(BoxedExpr::InitMemory(expr)).0)
    }

    /// Return the canonicalized expression equivalent to a `BoxedExpr::Ternary { cond, if_true,
    /// if_false }`.
    pub fn ternary(
        &mut self,
        mut cond: ConditionCode,
        mut if_true: Expr,
        mut if_false: Expr,
    ) -> Expr {
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

    /// Return the canonicalized expression equivalent to a `BoxedExpr::Linear { terms, constant }`.
    pub fn linear(
        &mut self,
        terms: impl IntoIterator<Item = (Expr, u64)>,
        mut constant: u64,
    ) -> Expr {
        let mut terms = terms.into_iter().peekable();
        if terms.peek().is_none() {
            return Expr::Constant(constant);
        }

        // Expand child linear expressions
        self.linear_scratch_buf.clear();
        for (expr, coef) in terms {
            if let Expr::Boxed(id) = expr
                && let BoxedExpr::Linear {
                    terms: child_terms,
                    constant: c,
                } = &self.store[id.0]
            {
                constant = constant.wrapping_add(c.wrapping_mul(coef));
                self.linear_scratch_buf.extend(child_terms.iter().map(|&(t, c)| (t, c * coef)));
                continue;
            }
            match expr {
                Expr::Constant(c) => constant = constant.wrapping_add(c.wrapping_mul(coef)),
                Expr::Unknown => return Expr::Unknown,
                expr => self.linear_scratch_buf.push((expr, coef)),
            };
        }
        // Sort terms in expression order
        self.linear_scratch_buf.sort_by(|a, b| a.0.cmp(&b.0));

        // Collapse terms together
        util::windows_mut(&mut self.linear_scratch_buf, |[(e1, c1), (e2, c2)]| {
            if e1 == e2 {
                *c2 = c1.wrapping_add(*c2);
                *c1 = 0;
            }
        });
        // Remove zero coef. terms while preserving order
        self.linear_scratch_buf.retain(|&(_, c)| c != 0);

        if self.linear_scratch_buf.is_empty() {
            return Expr::Constant(constant);
        }
        if constant == 0 && self.linear_scratch_buf.len() == 1 && self.linear_scratch_buf[0].1 == 1
        {
            return self.linear_scratch_buf[0].0;
        }

        let boxed = BoxedExpr::Linear {
            terms: self.linear_scratch_buf.clone(),
            constant,
        };
        Expr::Boxed(ExprId(self.store.insert_full(boxed).0))
    }
}

impl std::ops::Index<ExprId> for ExprHeap {
    type Output = BoxedExpr;

    fn index(&self, index: ExprId) -> &Self::Output {
        self.get(index).unwrap()
    }
}
