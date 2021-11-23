The *const generics* feature is landing in stable Rust from version 1.51. This feature has been longly-awaited, and you can get an idea of its possibilities here: [Rust 1.51 release notes](https://github.com/rust-lang/rust/blob/master/RELEASES.md#version-1510-2021-03-25)

I wanted to give it a try and thought that SHA2 message digest algorithms were a good test bed.

## SHA2 algorithm
I'm not going to dig into the details of the SHA message digest algorithm. It's a NIST standard (National Institute of Standards and Technology) labelled *FIPS-180*. You can get the detailed description in the NIST US government web site: [FIPS-180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)

In a nutshell, following is the general algorithm:

* initialize the hash value and constants
* pad the massage to be a multiple of 64 or 128 (i.e. 512 or 1024 bits)
* for each block of data:
    * prepare the message schedule using scrambling functions
    * for each of the 64 or 80 rounds, compute intermediate hash value
* output hash value

I'm only dealing here with the hash of byte-oriented messages.

What can be noticed are the similarities between SHA224/256 and SHA384/512 in terms of functions, initial hash values,
constants, padding:

| Tables        | SHA224/256           | SHA384/512  |
| ------------- |:-------------:|:-----:|
| block size    | 64 bytes | 128 bytes |
| padding    | 56 bytes boundary | 112 bytes boundary |
| Initialization vector    | 8 4-byte values | 8 8-byte values |
| K-constants      | 64 4-byte values | 80 8-byte values |
| rounds | 64      |    80 |
| functions | see below      |  see below |


## Rust implementation
Taking into account all those common features, we can define a SHA hash as:

```rust
// hash is either 256 or 512 bits but always 8 u32 or u64 integers
// T is either u32 or u64
pub struct Hash<T, const BLOCKSIZE: usize, const ROUNDS: usize> {
    pub k_constants: [T; ROUNDS],   // ROUNDS = 64 or 80
    pub hash: [T; 8],
    pub scramble_funcs: ScramblePool<T>, // scrambling functions σ etc
    pub block: [u8; BLOCKSIZE], // BLOCKSIZE = 64 or 128
}
```

### Scrambling functions
This terminology is not found in any NIST paper but I found it useful to name those functions. These are a combination of logical or, and, xor, bit rotation or bit shifting. But they are very similar:

* Ch(x,y,z) = (x & y) ^ (!x & z)
* Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
* Σ0 and Σ1 are the same, but with different shift values
* Σ0 and Σ1 are the same, but with different shift values

Using const generics, we can define those function generically, for *u32* or *u64* types but also for shifting values:

```rust
    // Σ(X) = RotR(X,A) ⊕ RotR(X,B) ⊕ RotR(X,C)
    #[allow(non_snake_case)]
    pub fn Σ<const A: u8, const B: u8, const C: u8>(x: T) -> T
    where
        T: BitAnd<Output = T>,
        T: BitXor<Output = T>,
        T: Shifter<T>,
        T: Copy,
    {
        x.right_rotate(A) ^ x.right_rotate(B) ^ x.right_rotate(C)
    }

    // σ(X) = RotR(X,A) ⊕ RotR(X,B) ⊕ X >> C
    #[allow(non_snake_case)]
    pub fn σ<const A: u8, const B: u8, const C: u8>(x: T) -> T
    where
        T: Shr<Output = T>,
        T: BitXor<Output = T>,
        T: Shifter<T>,
        T: Copy,
    {
        x.right_rotate(A) ^ x.right_rotate(B) ^ x.right_shift(C)
    }
```

where *right_rotate()* and *right_shift()* are trait functions implemented for *u32* and *u64*.

The scrambling functions are then gathered into a generic structure:

```rust
// Rust doesn't allow yet utf-8 symbol for variables
#[allow(non_snake_case)]
pub struct ScramblePool<T> {
    pub ch: FnScramble3<T>,
    pub maj: FnScramble3<T>,
    pub σ0: FnScramble1<T>,
    pub σ1: FnScramble1<T>,
    pub Σ0: FnScramble1<T>,
    pub Σ1: FnScramble1<T>,
}
```

### SHA2 algorithm
Because, of all this genericity, we can implement the SHA2 algorithm, bring either SHA256 or SHA512, totally generically. You can browse the code here:
https://github.com/dandyvica/sha

### Monomorphization
Depending of which algorithm you want to use, it's easy to define an alias for a specific type:

```rust
pub type Sha256 = Hash<u32, 64, 64>;
pub type Sha512 = Hash<u64, 128, 80>;
```

and implement the generic *Hash<T>* for both *u32* and *u64*:

```rust
// example for u32
impl Hash<u32, 64, 64> {
    pub fn new() -> Self {
        let iv: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        Hash {
            hash: iv,
            k_constants: Self::k_constants(),
            scramble_funcs: ScramblePool::<u32> {
                ch: Scramble::<u32>::Ch,
                maj: Scramble::<u32>::Maj,
                σ0: Scramble::<u32>::σ::<7, 18, 3>,
                σ1: Scramble::<u32>::σ::<17, 19, 10>,
                Σ0: Scramble::<u32>::Σ::<2, 13, 22>,
                Σ1: Scramble::<u32>::Σ::<6, 11, 25>,
            },
            block: [0u8; 64],
        }
    }

    pub fn k_constants() -> [u32; 64] {
        [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ]
    }
}

```


### Testing with SHA2 test vectors
The NIST site give a list of files to be tested, for integration test. When running *cargo t*, those tests are also run and sha digests verified.

I didn't implement SHA224 or SHA384 but is left as an exercice 😀

Hope this help !

> Photo by <a href="https://unsplash.com/@conscious_design?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText">Conscious Design</a> on <a href="https://unsplash.com/s/photos/chopping-board?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText">Unsplash</a>