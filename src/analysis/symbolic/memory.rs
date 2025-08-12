use fxhash::FxHashMap;

use crate::analysis::{
    ImageView,
    symbolic::expr::{BoxedExpr, Expr, ExprHeap},
};

#[derive(Default, Debug, Clone)]
pub struct Memory<I: ImageView> {
    image: I,
    writes: FxHashMap<Expr, Expr>,
    has_unk_write: bool,
}

impl<I: ImageView> Memory<I> {
    pub fn new(image: I) -> Self {
        Memory {
            image,
            writes: Default::default(),
            has_unk_write: false,
        }
    }

    pub fn read_u64(&self, address: &Expr, expr_heap: &mut ExprHeap) -> Expr {
        // TODO: Handle expressions with ternaries
        // Note: this can become exponential for linear combinations of ternaries
        if *address == Expr::Unknown || expr_heap.has_ternary(address) {
            Expr::Unknown
        }
        else if let Some(value) = self.writes.get(address) {
            *value
        }
        else if let Expr::Constant(c) = address
            && let Some(bytes) = self.image.read(*c, 8)
        {
            Expr::Constant(u64::from_le_bytes(bytes.try_into().unwrap()))
        }
        else {
            Expr::Boxed(expr_heap.init_memory(*address))
        }
    }

    pub fn write_u64(&mut self, address: &Expr, value: Expr, expr_heap: &mut ExprHeap) {
        // TODO: Handle expressions with ternaries
        // Note: this can become exponential for linear combinations of ternaries
        if *address == Expr::Unknown || expr_heap.has_ternary(address) {
            self.has_unk_write = true;
            self.writes.clear(); // we could have written anywhere!
        }
        else if let Expr::Boxed(id) = value
            && let BoxedExpr::InitMemory(a) = &expr_heap[id]
            && address == a
        {
            self.writes.remove(address);
        }
        else {
            self.writes.insert(*address, value);
        }
    }

    pub fn equal(&self, other: &Self) -> bool {
        if self.has_unk_write || other.has_unk_write {
            return false;
        }

        self.writes == other.writes
    }
}
