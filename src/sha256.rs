use crate::{
    scramble::{Scramble, ScramblePool},
    sha::Hash,
};

// aliases for sha values
pub type Sha256 = Hash<u32, 64, 64>;

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
                sigma0: Scramble::<u32>::sigma::<7, 18, 3>,
                sigma1: Scramble::<u32>::sigma::<17, 19, 10>,
                SIGMA0: Scramble::<u32>::SIGMA::<2, 13, 22>,
                SIGMA1: Scramble::<u32>::SIGMA::<6, 11, 25>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn block_padding_256() {
        // test "", length = 0
        let mut hash = Sha256::new();
        let result = hash.block_padding(0, 0);
        assert!(result.is_none());
        assert_eq!(hash.block[0], 0x80);
        for i in 1..63 {
            assert_eq!(hash.block[i], 0);
        }

        // test "abc", length = 3
        hash = Sha256::new();
        hash.block[0..3].clone_from_slice(b"abc");

        let result = hash.block_padding(3, 3);
        assert!(result.is_none());

        assert_eq!(hash.block[0], b'a');
        assert_eq!(hash.block[1], b'b');
        assert_eq!(hash.block[2], b'c');
        assert_eq!(hash.block[3], 0x80);
        for i in 4..62 {
            assert_eq!(hash.block[i], 0);
        }
        assert_eq!(hash.block[63], 0x18);

        // test "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", length = 56
        hash = Sha256::new();
        hash.block[0..56]
            .clone_from_slice(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let result = hash.block_padding(56, 56);
        assert!(result.is_some());
        assert_eq!(hash.block[56], 0x80);
        for i in 57..64 {
            assert_eq!(hash.block[i], 0);
        }

        let additional_block = result.unwrap();
        for i in 0..62 {
            assert_eq!(additional_block[i], 0);
        }
        assert_eq!(additional_block[62], 0x01);
        assert_eq!(additional_block[63], 0xc0);
    }

    #[test]
    fn test_vector_0() {
        let mut hash = Sha256::new();
        let _ = hash.block_padding(0, 0);
        hash.block_hash();

        assert_eq!(
            hash.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_vector_1() {
        let msg = b"abc";
        let cursor = Cursor::new(msg);
        let mut hash = Sha256::new();
        let result = hash.message_hash(3, cursor);
        assert!(result.is_ok());

        assert_eq!(
            hash.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_vector_2() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let cursor = Cursor::new(msg);
        let mut hash = Sha256::new();
        let result = hash.message_hash(56, cursor);
        assert!(result.is_ok());

        assert_eq!(
            hash.to_string(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_vector_3() {
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let cursor = Cursor::new(msg);
        let mut hash = Sha256::new();
        let result = hash.message_hash(112, cursor);
        assert!(result.is_ok());

        assert_eq!(
            hash.to_string(),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn test_vector_4() {
        let msg = &[b'a'; 1_000_000];
        let cursor = Cursor::new(msg);
        let mut hash = Sha256::new();
        let result = hash.message_hash(1_000_000, cursor);
        assert!(result.is_ok());

        assert_eq!(
            hash.to_string(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
}
