use std::mem;

pub struct SecureMem<T> {
    wrapped: T
}

impl<T: Copy> SecureMem<T> {
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
impl<T: Copy> Drop for SecureMem<T> {
    #[inline(never)]
    fn drop(&mut self) {
        unsafe {
            self.wrapped = mem::init();
        }
    }
}
