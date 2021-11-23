use std::ops::{BitAnd, BitXor, Not, Shr};

// functions used to rotate, shift etc
pub type FnScramble3<T> = fn(T, T, T) -> T;
pub type FnScramble1<T> = fn(T) -> T;

// need to implement this trait for u32/u64 rotate_right functions
pub trait Shifter<T> {
    fn right_rotate(&self, n: u8) -> T;
    fn right_shift(&self, n: u8) -> T;
}

impl Shifter<u32> for u32 {
    fn right_rotate(&self, n: u8) -> u32 {
        self.rotate_right(n as u32)
    }
    fn right_shift(&self, n: u8) -> u32 {
        self >> n as u32
    }
}

impl Shifter<u64> for u64 {
    fn right_rotate(&self, n: u8) -> u64 {
        self.rotate_right(n as u32)
    }
    fn right_shift(&self, n: u8) -> u64 {
        self >> n as u64
    }
}

pub struct Scramble<T> {
    _id: std::marker::PhantomData<T>,
}

// generic scrambling functions used in SHA calculations. Operate on u32 or u64
#[allow(non_snake_case)]
impl<T> Scramble<T> {
    // Ch(X,Y,Z) = (X ^ Y) ⊕ (!X ^ Z)
    #[allow(non_snake_case)]
    pub fn Ch(x: T, y: T, z: T) -> T
    where
        T: Not<Output = T>,
        T: BitAnd<Output = T>,
        T: BitXor<Output = T>,
        T: Copy,
    {
        (x & y) ^ (!x & z)
    }

    // Maj(X,Y,Z) = (X ^ Y) ⊕ (X ^ Z) ⊕ (Y ^ Z)
    #[allow(non_snake_case)]
    pub fn Maj(x: T, y: T, z: T) -> T
    where
        T: BitAnd<Output = T>,
        T: BitXor<Output = T>,
        T: Copy,
    {
        (x & y) ^ (x & z) ^ (y & z)
    }

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
}

#[allow(non_snake_case)]
pub struct ScramblePool<T> {
    pub ch: FnScramble3<T>,
    pub maj: FnScramble3<T>,
    pub σ0: FnScramble1<T>,
    pub σ1: FnScramble1<T>,
    pub Σ0: FnScramble1<T>,
    pub Σ1: FnScramble1<T>,
}

pub trait Scrambler<T> {
    fn σ<const A: u8, const B: u8, const C: u8>(&self) -> T
    where
        T: Shifter<T>,
        T: Copy;
}

impl<T> Scrambler<T> for T {
    fn σ<const A: u8, const B: u8, const C: u8>(&self) -> T
    where
        T: Shifter<T>,
        T: Copy,
    {
        self.right_shift(C)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn Ch() {
        let x: u32 = 0xAAAA;
        let y: u32 = 0xBBBB;
        let z: u32 = 0xCCCC;

        assert_eq!(x & y, 43690);
        assert_eq!(!x, 4294923605);
        assert_eq!(!x & z, 17476);

        assert_eq!(Scramble::<u32>::Ch(x, y, z), 61166);

        use super::Shifter;
        let _u = 3u32.right_rotate(4);
    }

    #[test]
    fn Maj() {
        let x: u32 = 0xAAAA;
        let y: u32 = 0xBBBB;
        let z: u32 = 0xCCCC;

        assert_eq!(x & y, 43690);
        assert_eq!(x & z, 34952);
        assert_eq!(y & z, 34952);

        assert_eq!(Scramble::<u32>::Maj(x, y, z), 43690);
    }

    #[test]
    fn Sigma0() {
        let x: u32 = 0b1111111111111111;

        let a = x.rotate_right(2);
        let b = x.rotate_right(13);
        let c = x.rotate_right(22);

        assert_eq!(a, 0b11000000000000000011111111111111);
        assert_eq!(b, 0b11111111111110000000000000000111);
        assert_eq!(c, 0b00000011111111111111110000000000);
        assert_eq!(a ^ b, 0b00111111111110000011111111111000);
        assert_eq!(a ^ b ^ c, 0b00111100000001111100001111111000);
        assert_eq!(
            Scramble::<u32>::Σ::<2, 13, 22>(x),
            0b00111100000001111100001111111000
        );
    }

    #[test]
    fn Sigma1() {
        let x: u32 = 0b1111111111111111;

        let a = x.rotate_right(6);
        let b = x.rotate_right(11);
        let c = x.rotate_right(25);

        assert_eq!(a, 0b11111100000000000000001111111111);
        assert_eq!(b, 0b11111111111000000000000000011111);
        assert_eq!(a ^ b, 0b00000011111000000000001111100000);
        assert_eq!(c, 0b00000000011111111111111110000000);
        assert_eq!(a ^ b, 0b00000011111000000000001111100000);
        assert_eq!(
            Scramble::<u32>::Σ::<6, 11, 25>(x),
            0b00000011100111111111110001100000
        );
    }

    #[test]
    fn σ0() {
        let x: u32 = 0b1111111111111111;

        let a = x.rotate_right(7);
        let b = x.rotate_right(18);
        let c = x >> 3;

        assert_eq!(a, 0b11111110000000000000000111111111);
        assert_eq!(b, 0b00111111111111111100000000000000);
        assert_eq!(a ^ b, 0b11000001111111111100000111111111);
        assert_eq!(c, 0b00000000000000000001111111111111);
        assert_eq!(
            Scramble::<u32>::σ::<7, 18, 3>(x),
            0b11000001111111111101111000000000
        );
    }

    #[test]
    fn σ1() {
        let x: u32 = 0b1111111111111111;

        let a = x.rotate_right(17);
        let b = x.rotate_right(19);
        let c = x >> 10;

        assert_eq!(a, 0b01111111111111111000000000000000);
        assert_eq!(b, 0b00011111111111111110000000000000);
        assert_eq!(a ^ b, 0b01100000000000000110000000000000);
        assert_eq!(c, 0b00000000000000000000000000111111);
        assert_eq!(
            Scramble::<u32>::σ::<17, 19, 10>(x),
            0b01100000000000000110000000111111
        );
    }
}
