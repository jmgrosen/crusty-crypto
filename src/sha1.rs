use HashFn;

use std::cmp::min;
use std::slice::MutableCloneableVector;
use serialize::hex::ToHex;

pub static BLOCK_SIZE: uint = 64;

struct Sha1_ {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    curlen: uint,
    length: u64,
}

pub struct Sha1 {
    s: Sha1_,
    buf: [u8, ..BLOCK_SIZE],
}

impl Sha1_ {
    fn compress(&mut self, data: &[u8]) {
        assert!(data.len() >= BLOCK_SIZE);
        let (mut a, mut b, mut c, mut d, mut e) = (self.h0, self.h1, self.h2, self.h3, self.h4);
        let mut w = [0, ..80];

        // copy state
        for i in range(0u, 16) {
            w[i] = get_32h!(data, i);
        }

        // expand it
        for i in range(16u, 80) {
            w[i] = rotl!(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        let mut i = 0;

        while i < 20 {
            sha1_ff0!(a, b, c, d, e, w[i]);
            i += 1;
            sha1_ff0!(e, a, b, c, d, w[i]);
            i += 1;
            sha1_ff0!(d, e, a, b, c, w[i]);
            i += 1;
            sha1_ff0!(c, d, e, a, b, w[i]);
            i += 1;
            sha1_ff0!(b, c, d, e, a, w[i]);
            i += 1;
        }

        while i < 40 {
            sha1_ff1!(a, b, c, d, e, w[i]);
            i += 1;
            sha1_ff1!(e, a, b, c, d, w[i]);
            i += 1;
            sha1_ff1!(d, e, a, b, c, w[i]);
            i += 1;
            sha1_ff1!(c, d, e, a, b, w[i]);
            i += 1;
            sha1_ff1!(b, c, d, e, a, w[i]);
            i += 1;
        }

        while i < 60 {
            sha1_ff2!(a, b, c, d, e, w[i]);
            i += 1;
            sha1_ff2!(e, a, b, c, d, w[i]);
            i += 1;
            sha1_ff2!(d, e, a, b, c, w[i]);
            i += 1;
            sha1_ff2!(c, d, e, a, b, w[i]);
            i += 1;
            sha1_ff2!(b, c, d, e, a, w[i]);
            i += 1;
        }

        while i < 80 {
            sha1_ff3!(a, b, c, d, e, w[i]);
            i += 1;
            sha1_ff3!(e, a, b, c, d, w[i]);
            i += 1;
            sha1_ff3!(d, e, a, b, c, w[i]);
            i += 1;
            sha1_ff3!(c, d, e, a, b, w[i]);
            i += 1;
            sha1_ff3!(b, c, d, e, a, w[i]);
            i += 1;
        }

        self.h0 += a;
        self.h1 += b;
        self.h2 += c;
        self.h3 += d;
        self.h4 += e;
    }
}

impl HashFn for Sha1 {
    fn create() -> Sha1 {
        Sha1 {
            s: Sha1_ {
                h0: 0x67452301,
                h1: 0xefcdab89,
                h2: 0x98badcfe,
                h3: 0x10325476,
                h4: 0xc3d2e1f0,
                curlen: 0,
                length: 0,
            },
            buf: [0, ..BLOCK_SIZE]
        }
    }

    fn update(&mut self, data: &[u8]) {
        assert!(self.s.curlen <= self.buf.len());
        let mut inlen = data.len();
        let mut cur_pos = 0;

        while inlen > 0 {
            if self.s.curlen == 0 && inlen >= BLOCK_SIZE {
                self.s.compress(data.slice_from(cur_pos));
                self.s.length += (BLOCK_SIZE as u64) * 8;
                cur_pos += BLOCK_SIZE;
                inlen -= BLOCK_SIZE;
            } else {
                let n = min(inlen, BLOCK_SIZE - self.s.curlen);
                self.buf.mut_slice_from(self.s.curlen).copy_from(data.slice(cur_pos, cur_pos + n));
                self.s.curlen = n;
                cur_pos += n;
                inlen -= n;
                if self.s.curlen == BLOCK_SIZE {
                    self.s.compress(self.buf);
                    self.s.length += (BLOCK_SIZE as u64) * 8;
                    self.s.curlen = 0;
                }
            }
        }
    }

    fn digest(mut self) -> Vec<u8> {
        assert!(self.s.curlen < self.buf.len());

        self.s.length += (self.s.curlen as u64) * 8;
        self.buf[self.s.curlen] = 0x80;
        self.s.curlen += 1;

        if self.s.curlen > 56 {
            while self.s.curlen < 64 {
                self.buf[self.s.curlen] = 0;
                self.s.curlen += 1;
            }
            self.s.compress(self.buf);
            self.s.curlen = 0;
        }

        while self.s.curlen < 56 {
            self.buf[self.s.curlen] = 0;
            self.s.curlen += 1;
        }

        store_64h!(self.s.length, self.buf.mut_slice_from(56));
        self.s.compress(self.buf);

        let mut out = Vec::from_elem(20, 0u8);
        store_32h!(self.s.h0, out.as_mut_slice());
        store_32h!(self.s.h1, out.mut_slice_from(4));
        store_32h!(self.s.h2, out.mut_slice_from(8));
        store_32h!(self.s.h3, out.mut_slice_from(12));
        store_32h!(self.s.h4, out.mut_slice_from(16));

        return out;
    }
}

#[test]
fn test_sha1() {
    static input: &'static [u8] = bytes!("hai thar");
    static output: &'static [u8] = &[62u8, 17, 175, 178, 74, 246, 12, 253, 21, 50,
                                    104, 45, 71, 224, 139, 175, 235, 114, 188, 175];
    let mut sha: Sha1 = HashFn::create();
    sha.update(input);
    let digest = sha.digest();
    assert_eq!(digest.as_slice(), output);
}

#[test]
fn test2() {
    let input = Vec::from_elem(10000, 'A' as u8);
    let mut sha: Sha1 = HashFn::create();
    sha.update(input.as_slice());
    let digest = sha.digest();
    assert_eq!(digest.as_slice().to_hex(), ~"bf6db7112b56812702e99d48a7b1dab62d09b3f6");
}
