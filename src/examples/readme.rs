extern crate rsa;

fn main() {
  let p = rsa::big_prime();
  println!("'{} is prime' is a {} statement!", p, rsa::is_prime(&p));
  //-> '{Some 1024-bit prime number} is prime' is a true statement!
}
