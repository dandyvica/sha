use crate::{
    scramble::{Scramble, ScramblePool},
    sha::Hash,
};

// aliases for sha values
pub type Sha512 = Hash<u64, 128, 80>;

impl Hash<u64, 128, 80> {
    pub fn new() -> Self {
        let iv: [u64; 8] = [
            0x6A09E667F3BCC908,
            0xBB67AE8584CAA73B,
            0x3C6EF372FE94F82B,
            0xA54FF53A5F1D36F1,
            0x510E527FADE682D1,
            0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B,
            0x5BE0CD19137E2179,
        ];
        Hash {
            hash: iv,
            k_constants: Self::k_constants(),
            scramble_funcs: ScramblePool::<u64> {
                ch: Scramble::<u64>::Ch,
                maj: Scramble::<u64>::Maj,
                sigma0: Scramble::<u64>::sigma::<1, 8, 7>,
                sigma1: Scramble::<u64>::sigma::<19, 61, 6>,
                SIGMA0: Scramble::<u64>::SIGMA::<28, 34, 39>,
                SIGMA1: Scramble::<u64>::SIGMA::<14, 18, 41>,
            },
            block: [0u8; 128],
        }
    }

    pub fn k_constants() -> [u64; 80] {
        [
            0x428A2F98D728AE22,
            0x7137449123EF65CD,
            0xB5C0FBCFEC4D3B2F,
            0xE9B5DBA58189DBBC,
            0x3956C25BF348B538,
            0x59F111F1B605D019,
            0x923F82A4AF194F9B,
            0xAB1C5ED5DA6D8118,
            0xD807AA98A3030242,
            0x12835B0145706FBE,
            0x243185BE4EE4B28C,
            0x550C7DC3D5FFB4E2,
            0x72BE5D74F27B896F,
            0x80DEB1FE3B1696B1,
            0x9BDC06A725C71235,
            0xC19BF174CF692694,
            0xE49B69C19EF14AD2,
            0xEFBE4786384F25E3,
            0x0FC19DC68B8CD5B5,
            0x240CA1CC77AC9C65,
            0x2DE92C6F592B0275,
            0x4A7484AA6EA6E483,
            0x5CB0A9DCBD41FBD4,
            0x76F988DA831153B5,
            0x983E5152EE66DFAB,
            0xA831C66D2DB43210,
            0xB00327C898FB213F,
            0xBF597FC7BEEF0EE4,
            0xC6E00BF33DA88FC2,
            0xD5A79147930AA725,
            0x06CA6351E003826F,
            0x142929670A0E6E70,
            0x27B70A8546D22FFC,
            0x2E1B21385C26C926,
            0x4D2C6DFC5AC42AED,
            0x53380D139D95B3DF,
            0x650A73548BAF63DE,
            0x766A0ABB3C77B2A8,
            0x81C2C92E47EDAEE6,
            0x92722C851482353B,
            0xA2BFE8A14CF10364,
            0xA81A664BBC423001,
            0xC24B8B70D0F89791,
            0xC76C51A30654BE30,
            0xD192E819D6EF5218,
            0xD69906245565A910,
            0xF40E35855771202A,
            0x106AA07032BBD1B8,
            0x19A4C116B8D2D0C8,
            0x1E376C085141AB53,
            0x2748774CDF8EEB99,
            0x34B0BCB5E19B48A8,
            0x391C0CB3C5C95A63,
            0x4ED8AA4AE3418ACB,
            0x5B9CCA4F7763E373,
            0x682E6FF3D6B2B8A3,
            0x748F82EE5DEFB2FC,
            0x78A5636F43172F60,
            0x84C87814A1F0AB72,
            0x8CC702081A6439EC,
            0x90BEFFFA23631E28,
            0xA4506CEBDE82BDE9,
            0xBEF9A3F7B2C67915,
            0xC67178F2E372532B,
            0xCA273ECEEA26619C,
            0xD186B8C721C0C207,
            0xEADA7DD6CDE0EB1E,
            0xF57D4F7FEE6ED178,
            0x06F067AA72176FBA,
            0x0A637DC5A2C898A6,
            0x113F9804BEF90DAE,
            0x1B710B35131C471B,
            0x28DB77F523047D84,
            0x32CAAB7B40C72493,
            0x3C9EBE0A15C9BEBC,
            0x431D67C49C100D4C,
            0x4CC5D4BECB3E42B6,
            0x597F299CFC657E2A,
            0x5FCB6FAB3AD6FAEC,
            0x6C44198C4A475817,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn block_padding_512() {
        // test "", length = 0
        let mut hash = Sha512::new();
        let result = hash.block_padding(0, 0);
        assert!(result.is_none());
        assert_eq!(hash.block[0], 0x80);
        for i in 1..127 {
            assert_eq!(hash.block[i], 0);
        }

        // new hash
        let mut hash = Sha512::new();

        // tests "abc" string
        hash.block[0..3].clone_from_slice(b"abc");

        let result = hash.block_padding(3, 3);
        assert!(result.is_none());

        assert_eq!(hash.block[0], b'a');
        assert_eq!(hash.block[1], b'b');
        assert_eq!(hash.block[2], b'c');
        assert_eq!(hash.block[3], 0x80);
        for i in 4..126 {
            assert_eq!(hash.block[i], 0);
        }
        assert_eq!(hash.block[127], 0x18);

        // test "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", length = 112
        hash.block[0..112]
            .clone_from_slice(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let result = hash.block_padding(112, 112);
        assert!(result.is_some());
        assert_eq!(hash.block[112], 0x80);
        for i in 113..128 {
            assert_eq!(hash.block[i], 0);
        }

        let additional_block = result.unwrap();
        for i in 0..126 {
            assert_eq!(additional_block[i], 0);
        }
        assert_eq!(additional_block[126], 0x03);
        assert_eq!(additional_block[127], 0x80);
    }

    #[test]
    fn test_vector_0() {
        let mut hash = Sha512::new();
        let _ = hash.block_padding(0, 0);
        hash.block_hash();

        assert_eq!(
            hash.to_string(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_vector_1() {
        let msg = b"abc";
        let cursor = Cursor::new(msg);
        let mut hash = Sha512::new();
        let result = hash.message_hash(3, cursor);
        assert!(result.is_ok());

        assert_eq!(
            hash.to_string(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_vector_2() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let cursor = Cursor::new(msg);
        let mut hash = Sha512::new();
        let result = hash.message_hash(56, cursor);
        assert!(result.is_ok());

        assert_eq!(
            hash.to_string(),
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
        );
    }

    #[test]
    fn test_vector_3() {
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let cursor = Cursor::new(msg);
        let mut hash = Sha512::new();
        let result = hash.message_hash(112, cursor);
        assert!(result.is_ok());

        assert_eq!(
            hash.to_string(),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    }

    #[test]
    fn test_vector_4() {
        let msg = &[b'a'; 1_000_000];
        let cursor = Cursor::new(msg);
        let mut hash = Sha512::new();
        let result = hash.message_hash(1_000_000, cursor);
        assert!(result.is_ok());

        assert_eq!(
            hash.to_string(),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        );
    }
}
