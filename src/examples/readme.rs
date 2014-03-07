extern crate rsa;

fn main() {
  let p = rsa::primes::big_prime();
  println!("'{} is prime' is a {} statement!", p, rsa::primes::is_prime(&p));
  //-> '{Some 1024-bit prime number} is prime' is a true statement!

  let message = ~"Some super secret scary message that is arbitrarily made up, but is more than 85, and less than 256 bytes long";
  let rsa = rsa::Rsa::new();
  let encrypted = rsa.encrypt(message);
  println!("The secret message is hidden inside of '{}'", encrypted); //-> A bunch of hex
  let decrypted = rsa.decrypt(encrypted);
  println!("But we can get it out! It is '{}'", decrypted); //-> super secret scary message
}
