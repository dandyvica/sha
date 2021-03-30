use std::convert::TryInto;
pub trait Modular<T> {
    fn add_modulo(&self, y: T) -> T;
    fn to_uint(buffer: &[u8]) -> T;
}

impl Modular<u32> for u32 {
    fn add_modulo(&self, y: u32) -> u32 {
        self.wrapping_add(y)
    }

    fn to_uint(buffer: &[u8]) -> u32 {
        #[cfg(target_endian = "little")]
        return u32::from_be_bytes(buffer.try_into().unwrap());

        #[cfg(target_endian = "big")]
        return u32::from_be_bytes(buffer.try_into().unwrap());
    }
}

impl Modular<u64> for u64 {
    fn add_modulo(&self, y: u64) -> u64 {
        self.wrapping_add(y)
    }

    fn to_uint(buffer: &[u8]) -> u64 {
        #[cfg(target_endian = "little")]
        return u64::from_be_bytes(buffer.try_into().unwrap());

        #[cfg(target_endian = "big")]
        return u64::from_be_bytes(buffer.try_into().unwrap());
    }
}
