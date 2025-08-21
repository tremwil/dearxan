use iced_x86::Encoder;

/// Reassembles lifted instructions such that they can be encoded in the same memory space that
/// the original instructions occupied.
pub struct Assembler {
    encoder: Encoder,
    usable_regions: Vec<(u64, usize)>,
    to_encode: Vec<usize>,
}
