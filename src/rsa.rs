use num::bigint::BigUint;

use num::One;
use num::Zero;

pub struct RsaPublicKey {
    n: BigUint,
    e: BigUint
}

fn power_mod(x: &BigUint, n: &BigUint, b: &BigUint) -> BigUint {
    let mut x = x.clone();
    let mut n = n.clone();
    let two = FromPrimitive::from_u64(2).unwrap();
    let one = One::one();
    let mut result: BigUint = One::one();
    while !n.is_zero() {
        if !(n & one).is_zero() {
            result = (result * x) % *b;
            n = n - one;
        }
        x = (x * x) % *b;
        n = n / two;
    }
    return result;
}

impl RsaPublicKey {
    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        power_mod(m, &self.e, &self.n)
    }
}

pub struct RsaPrivateKey {
    n: BigUint,
    d: BigUint
}

impl RsaPrivateKey {
    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        power_mod(c, &self.d, &self.n)
    }
}

pub fn gen_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    panic!()
}

#[test]
fn test_rsa_easy() {
    let pubkey = RsaPublicKey {
        n: FromPrimitive::from_u64(3233).unwrap(),
        e: FromPrimitive::from_u64(17).unwrap()
    };
    let privkey = RsaPrivateKey {
        n: FromPrimitive::from_u64(3233).unwrap(),
        d: FromPrimitive::from_u64(2753).unwrap()
    };
    let message: BigUint = FromPrimitive::from_u64(65).unwrap();
    let ciphertext = FromPrimitive::from_u64(2790).unwrap();

    assert_eq!(pubkey.encrypt(&message), ciphertext);
    assert_eq!(privkey.decrypt(&ciphertext), message);
}
