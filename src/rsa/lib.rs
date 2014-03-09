#[crate_id = "rsa#0.1.0-pre"];

#[comment = "Totally for-fun completely unusable RSA implementation"];
#[crate_type = "rlib"];

extern crate bignum;
extern crate serialize;

use std::num::ToStrRadix;
use bignum::{BigUint, ToBigUint};
use serialize::hex::{ToHex, FromHex};

pub mod primes;

pub enum PublicExponent {
  DefaultExponent,
  Exponent(uint)
}

#[deriving(Show)]
pub struct PublicKey {
  e: BigUint,
  n: BigUint
}

#[deriving(Show)]
pub struct PrivateKey {
  d: BigUint,
  n: BigUint
}

/// Generate RSA key-pair using public exponent e.
pub fn gen_keys(e: PublicExponent) -> (PublicKey, PrivateKey) {
  let e = match e {
    Exponent(e) => e,
    _           => 3u
  }.to_biguint().unwrap();
  let p = primes::rsa_prime(&e);
  let q = primes::rsa_prime(&e);
  let n = p * q;
  let one = 1u.to_biguint().unwrap();
  let et = (p - one) * (q - one);
  let d = primes::invmod(&e, &et).unwrap();
  
  ( PublicKey{ e: e, n: n.clone() }, PrivateKey{ d: d, n: n } )
}

impl PublicKey {
  fn encrypt_biguint(&self, m: &BigUint) -> BigUint {
    primes::mod_exp(m, &self.e, &self.n)
  }

  /// Encrypt a message using this public key
  pub fn encrypt(&self, m: ~str) -> ~str {
    assert!(m.char_len() < 256, "Message must be less than 256 bytes for RSA 2048");
    to_hex(&self.encrypt_biguint(&from_plaintext(m)))
  }
}

impl PrivateKey {
  fn decrypt_biguint(&self, c: &BigUint) -> BigUint {
    primes::mod_exp(c, &self.d, &self.n)
  }

  /// Decrypt a message using this private key
  pub fn decrypt(&self, m: ~str) -> ~str {
    to_plaintext(&self.decrypt_biguint(&from_hex(m)))
  }
}

/// Encoding helper functions

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

#[cfg(test)]
mod test_rsa {
  use super::{Default, Exponent, gen_keys, from_hex, to_hex, from_plaintext, to_plaintext};
  use bignum::ToBigUint;

  #[test]
  fn test_conversions() {
    assert_eq!(from_plaintext(~"abcd"), 1633837924u.to_biguint().unwrap()) 
    assert_eq!(from_hex(~"61626364"), 1633837924u.to_biguint().unwrap()) 
    assert_eq!(to_plaintext(&1633837924u.to_biguint().unwrap()), ~"abcd") 
    assert_eq!(to_hex(&1633837924u.to_biguint().unwrap()), ~"61626364") 
  }

  #[test]
  fn test_encrypt_decrypt_default() {
    let (public, private) = gen_keys(DefaultExponent);
    let m = ~"super secret message";
    let encrypted = public.encrypt(m.clone());
    let decrypted = private.decrypt(encrypted);
    assert_eq!(m, decrypted);
  }

  #[test]
  fn test_encrypt_decrypt_five() {
    let (public, private) = gen_keys(Exponent(5u));
    let m = ~"super secret message";
    let encrypted = public.encrypt(m.clone());
    let decrypted = private.decrypt(encrypted);
    assert_eq!(m, decrypted);
  }
}
