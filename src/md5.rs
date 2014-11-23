use HashFn;

pub struct Md5 {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    total: [u32, ..2],
    buflen: u32,
    buffer: [u32, ..32]
}

impl HashFn for Md5 {
    fn create() -> Md5 {
        Md5 {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
            total: [0, 0],
            buflen: 0,
            buffer: [0, ..32]
        }
    }

    fn update(&mut self, data: &[u8]) {
        if self.buflen != 0 {

        }
    }

    fn digest(self) -> Vec<u8> {
        let mut out = Vec::from_elem(16, 0u8);
        store_32h!(self.a, out.mut_slice(0, 4));
        store_32h!(self.b, out.mut_slice(4, 8));
        store_32h!(self.c, out.mut_slice(8, 12));
        store_32h!(self.d, out.mut_slice(12, 16));
        return out;
    }
}
