pub trait KeySize {
    /// In bytes, not bits. (The Option<&Self> is a workaround for a Rust bug.)
    fn ksize(_: Option<&Self>) -> uint;
}

pub struct KeySize128;
impl KeySize for KeySize128 {
    fn ksize(_: Option<&KeySize128>) -> uint { 16 }
}

pub struct KeySize192;
impl KeySize for KeySize192 {
    fn ksize(_: Option<&KeySize192>) -> uint { 24 }
}

pub struct KeySize256;
impl KeySize for KeySize256 {
    fn ksize(_: Option<&KeySize256>) -> uint { 32 }
}

pub trait BlockCipher {
    /// The size of blocks in bytes. (Note that the block size should be the
    /// same for a given type, and the argument is simply a workaround for a
    /// Rust bug.)
    fn block_size(_: Option<&Self>) -> uint;

    /// The size of input and output must be equal to the block size.
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);

    /// The size of input and output must be equal to the block size.
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);

    fn encrypt_ecb(&self, ptext: &[u8]) -> Vec<u8> {
        if ptext.len() == 0 {
            return Vec::new();
        }
        let bs = BlockCipher::block_size(None::<&Self>);
        assert!(ptext.len() % bs == 0);

        let mut out = Vec::from_elem(ptext.len(), 0u8);

        for i in range(0, ptext.len() / bs) {
            self.encrypt_block(ptext.slice(i*bs, (i+1)*bs),
                               out.mut_slice(i*bs, (i+1)*bs));
        }

        return out;
    }

    fn decrypt_ecb(&self, ctext: &[u8]) -> Vec<u8> {
        if ctext.len() == 0 {
            return Vec::new();
        }
        let bs = BlockCipher::block_size(None::<&Self>);
        assert!(ctext.len() % bs == 0);

        let mut out = Vec::from_elem(ctext.len(), 0u8);

        for i in range(0, ctext.len() / bs) {
            self.decrypt_block(ctext.slice(i*bs, (i+1)*bs),
                               out.mut_slice(i*bs, (i+1)*bs));
        }

        return out;
    }

    fn encrypt_cbc(&self, iv: &[u8], ptext: &[u8]) -> Vec<u8> {
        if ptext.len() == 0 {
            return Vec::new();
        }
        let bs = BlockCipher::block_size(None::<&Self>);
        assert!(iv.len() == bs);
        assert!(ptext.len() % bs == 0);

        let mut ctext = Vec::from_elem(ptext.len(), 0u8);
        let mut xored = Vec::from_elem(bs, 0u8);

        bxor_into(iv, ptext.slice_to(bs), xored.as_mut_slice());
        self.encrypt_block(xored.as_slice(), ctext.mut_slice_to(bs));

        for i in range(1, ptext.len() / bs) {
            bxor_into(ptext.slice(i*bs, (i+1)*bs),
                      ctext.slice((i-1)*bs, i*bs),
                      xored.as_mut_slice());
            self.encrypt_block(xored.as_slice(),
                               ctext.mut_slice(i*bs, (i+1)*bs));
        }

        return ctext;
    }

    fn decrypt_cbc(&self, iv: &[u8], ctext: &[u8]) -> Vec<u8> {
        if ctext.len() == 0 {
            return Vec::new();
        }
        let bs = BlockCipher::block_size(None::<&Self>);
        assert!(iv.len() == bs);
        assert!(ctext.len() % bs == 0);

        let mut ptext = Vec::from_elem(ctext.len(), 0u8);

        let mut scratch = Vec::from_elem(bs, 0u8);
        self.decrypt_block(ctext.slice_to(bs), scratch.as_mut_slice());
        bxor_into(scratch.as_slice(), iv, ptext.mut_slice_to(bs));

        for i in range(1, ctext.len() / bs) {
            self.decrypt_block(ctext.slice(i*bs, (i+1)*bs), scratch.as_mut_slice());
            bxor_into(scratch.as_slice(), ctext.slice((i-1)*bs, i*bs),
                      ptext.mut_slice(i*bs, (i+1)*bs));
        }

        return ptext;
    }
}

fn bxor_into(one: &[u8], two: &[u8], out: &mut [u8]) {
    for (o, (&a, &b)) in out.mut_iter().zip(one.iter().zip(two.iter())) {
        *o = a ^ b;
    }
}

pub fn ksize<KS: KeySize>() -> uint {
    KeySize::ksize(None::<&KS>)
}

pub trait StreamCipher {
    fn combine(&mut self, input: &[u8], output: &mut [u8]);

    #[inline(always)]
    fn encrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::from_elem(input.len(), 0u8);
        self.combine(input, out.as_mut_slice());
        return out;
    }

    #[inline(always)]
    fn decrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::from_elem(input.len(), 0u8);
        self.combine(input, out.as_mut_slice());
        return out;
    }
}
