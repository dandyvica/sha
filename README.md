# Implementing SHA2 (256/512) algorithm with Rust const generics

Refer to https://dev.to/dandyvica/implementing-sha2-256-512-algorithm-with-rust-const-generics-5ap

it has been updated replacing *sigma* and *SIGMA* functions with *σ* and *Σ* functions respectively, leveraging from unicode variable names or function names, which makes more sense here:

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

The algorithm here is totally generic: the same for sha256 or sha512.
