extern crate rsa;

fn main() {
  let p = rsa::primes::big_prime(1024);
  println!("'{} is prime' is a {} statement!", p, rsa::primes::is_prime(&p));
  //-> '{Some 1024-bit prime number} is prime' is a true statement!

  let message = ~"Some super secret scary message that I don't want anybody to see!";
  let (public_key, private_key) = rsa::gen_keys_default();
  let encrypted = public_key.encrypt(message);
  println!("The secret message is hidden inside of '{}'", encrypted); //-> A bunch of hex
  let decrypted = private_key.decrypt(encrypted);
  println!("But we can get it out! It is '{}'", decrypted); //-> super secret scary message
}
