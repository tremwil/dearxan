pub struct FmtSigned<T: Copy + Into<i128>>(T);

pub trait AsFmtSigned: Copy + Into<i128> {
    fn format_signed(self) -> FmtSigned<Self> {
        FmtSigned(self)
    }
}

impl<T: Copy + Into<i128>> AsFmtSigned for T {}

impl<T: Copy + Into<i128>> std::fmt::Debug for FmtSigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num: i128 = self.0.into();
        if num >= 0 {
            f.write_str("+")?;
            std::fmt::Debug::fmt(&num, f)
        }
        else {
            f.write_str("-")?;
            std::fmt::Debug::fmt(&num.wrapping_neg(), f)
        }
    }
}

impl<T: Copy + Into<i128>> std::fmt::Display for FmtSigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num: i128 = self.0.into();
        if num >= 0 {
            f.write_str("+")?;
            std::fmt::Display::fmt(&num, f)
        }
        else {
            f.write_str("-")?;
            std::fmt::Display::fmt(&num.wrapping_neg(), f)
        }
    }
}

impl<T: Copy + Into<i128>> std::fmt::LowerHex for FmtSigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num: i128 = self.0.into();
        if num >= 0 {
            f.write_str("+")?;
            std::fmt::LowerHex::fmt(&num, f)
        }
        else {
            f.write_str("-")?;
            std::fmt::LowerHex::fmt(&num.wrapping_neg(), f)
        }
    }
}

impl<T: Copy + Into<i128>> std::fmt::UpperHex for FmtSigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num: i128 = self.0.into();
        if num >= 0 {
            f.write_str("+")?;
            std::fmt::UpperHex::fmt(&num, f)
        }
        else {
            f.write_str("-")?;
            std::fmt::UpperHex::fmt(&num.wrapping_neg(), f)
        }
    }
}
