use cipher::StreamCipher;

pub struct ChaCha20 {
    state: [u32, ..16],
    blocks: [u8, ..64],
    index: u8,
}

impl ChaCha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
        let mut chacha = ChaCha20 {
            state: [
                0x61707865,
                0x3320646e,
                0x79622d32,
                0x6b206574,
                unpack!(key, 0),
                unpack!(key, 1),
                unpack!(key, 2),
                unpack!(key, 3),
                unpack!(key, 4),
                unpack!(key, 5),
                unpack!(key, 6),
                unpack!(key, 7),
                0,
                0,
                unpack!(nonce, 0),
                unpack!(nonce, 1),
                ],
            blocks: [0, ..64], // uninit()?
            index: 0,
        };
        chacha.advance();
        return chacha;
    }
    fn run_all_rounds(&mut self) {
        let mut state = self.state;
        for _ in range(0i, 10) {
            cc20_qround!(state, 0, 4,  8, 12);
            cc20_qround!(state, 1, 5,  9, 13);
            cc20_qround!(state, 2, 6, 10, 14);
            cc20_qround!(state, 3, 7, 11, 15);
            cc20_qround!(state, 0, 5, 10, 15);
            cc20_qround!(state, 1, 6, 11, 12);
            cc20_qround!(state, 2, 7,  8, 13);
            cc20_qround!(state, 3, 4,  9, 14);
        }
        for i in range(0u, 16) {
            state[i] += self.state[i];
        }
        self.blocks = transmute_array(state);
    }
    fn advance(&mut self) {
        self.run_all_rounds();
        self.index = 0;
        let i = self.state[12] + 1;
        self.state[12] = i;
        if i == 0 {
            self.state[13] += 1;
        }
    }
}

#[cfg(target_endian = "little")]
fn transmute_array(input: [u32, ..16]) -> [u8, ..64] {
    unsafe { ::std::mem::transmute(input) }
}

impl StreamCipher for ChaCha20 {
    fn combine(&mut self, input: &[u8], output: &mut [u8]) {
        for (o, &i) in output.iter_mut().zip(input.iter()) {
            *o = self.blocks[self.index as uint] ^ i;
            self.index += 1;
            if self.index == 64 {
                self.advance();
            }
        }
    }
}

impl Drop for ChaCha20 {
    #[inline(never)]
    fn drop(&mut self) {
        for b in self.state.iter_mut() {
            *b = 0;
        }
    }
}

#[test]
fn test_chacha() {
    use serialize::hex::FromHex;
    static KEY: &'static str = "0000000000000000000000000000000000000000000000000000000000000001";
    static NONCE: &'static str = "0000000000000000";
    static KEYSTREAM: &'static str = "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963";
    let (key, nonce, keystream) = (KEY.from_hex().unwrap(),
                                   NONCE.from_hex().unwrap(),
                                   KEYSTREAM.from_hex().unwrap());

    let mut chacha = ChaCha20::new(key[], nonce[]);
    let output = chacha.encrypt(Vec::from_elem(keystream.len(), 0u8).as_slice());
    assert_eq!(output.as_slice(), keystream.as_slice());
}

#[test]
fn test_chacha2() {
    use serialize::hex::FromHex;
    static KEY: &'static str = "0000000000000000000000000000000000000000000000000000000000000000";
    static NONCE: &'static str = "0100000000000000";
    static KEYSTREAM: &'static str = "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b";
    let (key, nonce, keystream) = (KEY.from_hex().unwrap(),
                                   NONCE.from_hex().unwrap(),
                                   KEYSTREAM.from_hex().unwrap());

    let mut chacha = ChaCha20::new(key[], nonce[]);
    let output = chacha.encrypt(Vec::from_elem(keystream.len(), 0u8).as_slice());
    assert_eq!(output.as_slice(), keystream.as_slice());
}
