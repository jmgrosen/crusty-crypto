use std::num::Int;

pub struct SecureMem<T> {
    wrapped: T
}

impl<T: CleanOut> SecureMem<T> {
    pub fn new(val: T) -> SecureMem<T> {
        SecureMem { wrapped: val }
    }
}

impl<T> Deref<T> for SecureMem<T> {
    fn deref<'a>(&'a self) -> &'a T {
        &self.wrapped
    }
}

impl<T> DerefMut<T> for SecureMem<T> {
    fn deref_mut<'a>(&'a mut self) -> &'a mut T {
        &mut self.wrapped
    }
}

#[unsafe_destructor]
impl<T: CleanOut> Drop for SecureMem<T> {
    #[inline(never)]
    fn drop(&mut self) {
        self.wrapped.clear_self();
    }
}

trait CleanOut {
    fn clear_self(&mut self);
}

impl CleanOut for [u32, ..16] {
    fn clear_self(&mut self) {
        for b in self.iter_mut() {
            *b = 0;
        }
    }
}

impl<T: Int> CleanOut for Vec<T> {
    fn clear_self(&mut self) {
        for b in self.iter_mut() {
            *b = Int::zero();
        }
    }
}
