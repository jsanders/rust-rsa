Totally for-fun RSA implementation
----------------------------------

__Pretty please don't use this for anything requiring real security. I am building it to gain an understanding of how RSA works and how attacks on it function, and as such it is almost certainly vulnerable to many of them__

This library implements RSA and RSA-related functionality. Currently, you can generate 1024-bit prime numbers, check any bignum::BigUint for primality, encrypt, and decrypt messages with very naive 1024-bit RSA:

```rust
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
```

Installation
------------

To build and test:

```sh
make deps && make test
```

To install into system rustlib:

```sh
make install
```

To build examples:

```sh
make examples
```

Examples can then be run from `build/examples`. (Note: building examples also installs the library system-wide, which may not be desired.)
