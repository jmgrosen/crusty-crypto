#![feature(slicing_syntax)]
#![feature(macro_rules)]
#![feature(phase)]
#![feature(unsafe_destructor)]

#[phase(plugin, link)]
extern crate log;
extern crate serialize;
extern crate num;

mod macros;
pub mod sha1;
pub mod aes;
pub mod cipher;
mod securemem;
pub mod chacha20;
pub mod rsa;

pub trait HashFn {
    fn create() -> Self;
    fn update(&mut self, data: &[u8]);
    fn digest(self) -> Vec<u8>;
}
