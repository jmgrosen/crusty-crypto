pub trait ConstantTimeEq {
    /// Returns 1 on equal, something else on non-equal
    fn const_time_eq_(&self, other: &Self) -> int;

    fn const_time_eq(&self, other: &Self) -> bool {
        self.const_time_eq_(other) == 1
    }
}

impl ConstantTimeEq for u8 {
    #[inline]
    fn const_time_eq_(&self, &other: &u8) -> int {
        let mut z = !(*self ^ other);
        z &= z >> 4;
        z &= z >> 2;
        z &= z >> 1;

        z as int
    }
}

impl<'a> ConstantTimeEq for &'a [u8] {
    fn const_time_eq_(&self, other: & &'a [u8]) -> int {
        if self.len() == other.len() {
            0
        } else {
            self.iter().zip(other.iter())
                .fold(0, |run, (&a, &b)| run | (a ^ b))
                .const_time_eq_(&0)
        }
    }
}
