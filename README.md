Totally for-fun RSA implementation
----------------------------------

__Pretty please don't use this for anything requiring real security. I am building it to gain an understanding of how RSA works and how attacks on it function, and as such it is almost certainly vulnerable to many of them__

This library implements RSA and RSA-related functionality. Currently, you can generate 1024-bit prime numbers, and check any bignum::BigUint for primality:

```rust
extern crate rsa;

fn main() {
  let p = rsa::big_prime();
  println!("'{} is prime' is a {} statement!", p, rsa::is_prime(&p));
  //-> '{Some 1024-bit prime number} is prime' is a true statement!
}
```

Installation
------------

To build and test:

```sh
make
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
