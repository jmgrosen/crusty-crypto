#![feature(macro_rules)]
#![feature(phase)]

#[phase(syntax, link)]
extern crate log;
extern crate serialize;

mod macros;
mod sha1;
mod aes;
mod cipher;
mod securemem;
mod chacha20;

pub trait HashFn {
    fn create() -> Self;
    fn update(&mut self, data: &[u8]);
    fn digest(self) -> Vec<u8>;
}
