#[crate_id = "rsa#0.1.0-pre"];

#[comment = "Totally for-fun completely unusable RSA implementation"];
#[crate_type = "rlib"];

extern crate bignum;
extern crate serialize;

use std::num::ToStrRadix;
use bignum::{BigUint, ToBigUint};
use serialize::hex::{ToHex, FromHex};

pub mod primes;

#[deriving(Show)]
pub struct RsaKey(BigUint, BigUint);

#[deriving(Show)]
pub struct Rsa {
  public:  RsaKey,
  private: RsaKey
}

impl Rsa {
  pub fn new() -> Rsa {
    let e = 3u.to_biguint().unwrap();
    let p = primes::rsa_prime(&e);
    let q = primes::rsa_prime(&e);
    let n = p * q;
    let one = 1u.to_biguint().unwrap();
    let et = (p - one) * (q - one);
    let d = primes::invmod(&e, &et).unwrap(); // Mathematically, shouldn't ever fail
    Rsa{ public: RsaKey(e, n.clone()), private: RsaKey(d, n) }
  }

  fn to_hex(m: &BigUint) -> ~str {
    m.to_str_radix(16)
  }

  fn to_plaintext(m: &BigUint) -> ~str {
    m.to_str_radix(16).from_hex().unwrap().into_ascii().into_str()
  }

  fn from_plaintext(m: ~str) -> BigUint {
    BigUint::from_str_radix(m.as_bytes().to_hex(), 16).unwrap()
  }

  fn from_hex(m: ~str) -> BigUint {
    BigUint::from_str_radix(m, 16).unwrap()
  }

  fn encrypt_biguint(&self, m: &BigUint) -> BigUint {
    let RsaKey(ref e, ref n) = self.public;
    primes::mod_exp(m, e, n)
  }

  fn decrypt_biguint(&self, c: &BigUint) -> BigUint {
    let RsaKey(ref d, ref n) = self.private;
    primes::mod_exp(c, d, n)
  }

  pub fn encrypt(&self, m: ~str) -> ~str {
    Rsa::to_hex(&self.encrypt_biguint(&Rsa::from_plaintext(m)))
  }

  pub fn decrypt(&self, m: ~str) -> ~str {
    Rsa::to_plaintext(&self.decrypt_biguint(&Rsa::from_hex(m)))
  }

}

#[cfg(test)]
mod test_rsa {
  use super::Rsa;
  use bignum::ToBigUint;

  #[test]
  fn test_conversions() {
    assert_eq!(Rsa::from_plaintext(~"abcd"), 1633837924u.to_biguint().unwrap()) 
    assert_eq!(Rsa::from_hex(~"61626364"), 1633837924u.to_biguint().unwrap()) 
    assert_eq!(Rsa::to_plaintext(&1633837924u.to_biguint().unwrap()), ~"abcd") 
    assert_eq!(Rsa::to_hex(&1633837924u.to_biguint().unwrap()), ~"61626364") 
  }

  #[test]
  fn test_encrypt_decrypt() {
    let rsa = Rsa::new();
    let m = ~"super secret message";
    let encrypted = rsa.encrypt(m.clone());
    let decrypted = rsa.decrypt(encrypted);
    assert_eq!(m, decrypted);
  }
}
