extern crate std;
use std::num::{Zero, One};
use std::rand::task_rng;
use std::iter::{count, range_step_inclusive};
use bignum::{BigUint, RandBigInt, ToBigUint, BigInt, ToBigInt};

// Find all prime numbers less than n
fn small_primes(bound: uint) -> ~[uint] {
  // num is considered prime as long as primes[num] is true
  // Start with all evens besides 2 filtered out
  let mut primes = std::vec::from_fn(bound+1, |num| num == 2 || num & 1 != 0);

  // Start at 3 and step by 2 because we've already filtered multiples of 2
  for num in count(3u, 2) {
    if num * num > bound { break; } // Break when we've checked everything <= bound
    if !primes[num] { continue; }   // We know num is composite, so move on

    // We know num is prime, so mark its multiples composite
    // We can start at num^2 because smaller non-primes have already been eliminated
    for j in range_step_inclusive(num*num, bound, num) { primes[j] = false; }
  }

  primes.
    move_iter().
    enumerate().
    skip(2).
    filter_map(|(i, p)| if p {Some(i)} else {None}).
    collect::<~[uint]>()
}

// Modular exponentiation by squaring
pub fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
  let (zero, one): (BigUint, BigUint) = (Zero::zero(), One::one());
  let mut result = one.clone();
  let mut baseAcc = base.clone();
  let mut exponentAcc = exponent.clone();

  while exponentAcc > zero {
    // Accumulate current base if current exponent bit is 1
    if (exponentAcc & one) == one {
      result = result.mul(&baseAcc);
      result = result.rem(modulus);
    }
    // Get next base by squaring
    baseAcc = baseAcc * baseAcc;
    baseAcc = baseAcc % *modulus;

    // Get next bit of exponent
    exponentAcc = exponentAcc.shr(&1);
  }

  result
}

// Given an even `n`, find first `s` and odd `d` such that n = 2^s*d
fn rewrite(n: &BigUint) -> (BigUint, BigUint) {
  let mut d = n.clone();
  let mut s: BigUint = Zero::zero();
  let one: BigUint = One::one();
  let two = one + one;

  while d.is_even() {
    d = d / two;
    s = s + one;
  }
  (s, d)
}

// Rabin-Miller until probability of false-positive is < 2^-128
fn rabin_miller(candidate: &BigUint) -> bool {
  let zero: BigUint = Zero::zero();
  let one: BigUint = One::one();
  let two = one + one;

  // Rabin-Miller has trouble with even numbers, so special case them
  if candidate == &two   { return true }
  if candidate.is_even() { return false }

  let (s, d) = rewrite(&(candidate - one));
  // Probability of false-positive is 2^-k
  let mut k = 0;
  while k < 128 {
    let basis = task_rng().gen_biguint_range(&two, candidate);
    let mut v = mod_exp(&basis, &d, candidate);
    if v != one && v != (candidate - one) {
      let mut i = zero.clone();
      loop {
        v = mod_exp(&v, &two, candidate);
        if v == (candidate - one) {
          break;
        } else if v == one || i == (s - one) {
          return false
        }
        i = i + one;
      }
    }
    k += 2;
  }
  true
}

pub fn is_prime(candidate: &BigUint) -> bool {
  for p in small_primes(1000).move_iter() {
    let bigp = &p.to_biguint().unwrap();
    if candidate == bigp {
      return true;
    } else if bigp.divides(candidate) {
      return false;
    }
  }
  rabin_miller(candidate)
}

pub fn big_prime(size: uint) -> BigUint {
  let one: BigUint = One::one();
  let two = one + one;

  let mut rng = task_rng();
  let mut candidate = rng.gen_biguint(size);
  if candidate.is_even() {
    candidate = candidate + one;
  }
  while !is_prime(&candidate) {
    candidate = candidate + two;
  }
  candidate
}

/// An prime suitable for RSA with exponent `e`
/// The prime `p` - 1 can't be a multiple of `e`
pub fn rsa_prime(size: uint, e: &BigUint) -> BigUint {
  let one: BigUint = One::one();
  loop {
    let p = big_prime(size);
    if p.modulus(e) != one { return p }
  }
}

/// Extended Euclidean GCD algorithm
/// Returns k, u,and v such that ua + vb = k, where k is the gcd of a and b
pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
  let (zero, one): (BigInt, BigInt) = (Zero::zero(), One::one());
  // u_a, v_a, u_b, v_b = 1, 0, 0, 1
  let (mut u_a, mut v_a, mut u_b, mut v_b) = (one.clone(), zero.clone(), zero.clone(), one.clone());
  let (mut aa, mut bb) = (a.to_bigint().unwrap(), b.to_bigint().unwrap());

  while aa != zero {
    let q = bb / aa;

    let new_a = bb - q * aa;
    bb = aa;
    aa = new_a;

    let new_u_a = u_b - q * u_a; 
    u_b = u_a;
    u_a = new_u_a;

    let new_v_a = v_b - q * v_a; 
    v_b = v_a;
    v_a = new_v_a;
  }
  (bb, u_b, v_b)
}

/// Find the inverse of `x` under the modulus `modulus`
pub fn invmod(x: &BigUint, modulus: &BigUint) -> Option<BigUint> {
  let (gcd, inverse, _) = extended_gcd(x, modulus);
  if gcd == One::one() {
    // Shouldn't fail if math works right
    Some(inverse.modulus(modulus))
  } else {
    None
  }
}

#[cfg(test)]
mod test_primes {
  use super::{small_primes, mod_exp, is_prime, big_prime, rsa_prime, invmod};
  use bignum::{BigUint, ToBigUint};
  use std::from_str::FromStr;
  use std::num::{One};

  #[test]
  fn test_small_primes() {
    assert_eq!(small_primes(20), ~[2, 3, 5, 7, 11, 13, 17, 19]);
  }

  #[test]
  fn test_mod_exp() {
    let two = 2u.to_biguint().unwrap();
    let three = 3u.to_biguint().unwrap();
    let four = 4u.to_biguint().unwrap();
    let seven = 7u.to_biguint().unwrap();
    let one: BigUint = One::one();
    assert_eq!(mod_exp(&two, &two, &seven), four);
    assert_eq!(mod_exp(&two, &three, &seven), one);
  }

  #[test]
  fn test_is_prime() {
    // Trivial composites
    assert!(!is_prime(&27u.to_biguint().unwrap()));
    assert!(!is_prime(&1000u.to_biguint().unwrap()));

    // Big composite
    let known_composite_str =
      "5998532537771751919223292779480088814208363735733315189796\
       0101571924729278483053936094631318228299245382944144514257\
       1892041750575871002135423472834270012679636490411466324906\
       0917779866191551702619628937679141866044903982454458080353\
       0712317148561932424450480592940247925414152689953357952137\
       58437410764432671";
    let known_composite: BigUint = FromStr::from_str(known_composite_str).unwrap();
    assert!(!is_prime(&known_composite));

    // Small primes
    for p in small_primes(1000).move_iter() {
      assert!(is_prime(&p.to_biguint().unwrap()));
    }

    // Big primes
    assert!(is_prime(&15486869u.to_biguint().unwrap()));
    assert!(is_prime(&179425357u.to_biguint().unwrap()));
    let known_prime_str =
      "1185953636795374682612582767575507043186511556015932992921\
      98496313960907653004730006758459999825003212944725610469590\
      67402012450624977056639426083223780925249450568325586119944\
      94823851964743424816413015031211427409331862791112093760615\
      35491003888763334916103110474472949854230628809878558752830\
      476310536476569";
    let known_prime: BigUint = FromStr::from_str(known_prime_str).unwrap();
    assert!(is_prime(&known_prime));
  }

  #[test]
  fn test_big_prime() {
    let size = 1024;
    let p = big_prime(size);

    assert!(p.bits() >= size - 1);
    assert!(is_prime(&p));
  }

  #[test]
  fn test_rsa_prime() {
    let one = 1u.to_biguint().unwrap();
    let three = 3u.to_biguint().unwrap();
    let five = 5u.to_biguint().unwrap();
    let size = 1024;
    assert!(rsa_prime(size, &three).modulus(&three) != one);
    assert!(rsa_prime(size, &five).modulus(&five) != one);
  }

  #[test]
  fn test_invmod() {
    let three = 3u.to_biguint().unwrap();
    let five = 5u.to_biguint().unwrap();
    let six = 6u.to_biguint().unwrap();
    let seven = 7u.to_biguint().unwrap();
    let fortyone = 41u.to_biguint().unwrap();

    assert_eq!(invmod(&three, &seven).unwrap(), five);
    assert_eq!(invmod(&seven, &fortyone).unwrap(), six);
    assert_eq!(invmod(&three, &six), None);
  }
}
