#[allow(non_snake_case)]
use std::default::Default;
use std::fmt::{Display, LowerHex};
use std::io::BufRead;

use crate::convert::Modular;
use crate::scramble::ScramblePool;

// hash is either 256 or 512 bits but always 8 u32 or u64 integers
// T is either u32 or u64
pub struct Hash<T, const BLOCKSIZE: usize, const ROUNDS: usize> {
    pub k_constants: [T; ROUNDS],   // ROUNDS = 64 or 80
    pub hash: [T; 8],
    pub scramble_funcs: ScramblePool<T>, // scrambling functions sigma etc
    pub block: [u8; BLOCKSIZE], // BLOCKSIZE = 64 or 128
}

#[allow(non_snake_case)]
impl<T, const BLOCKSIZE: usize, const ROUNDS: usize> Hash<T, BLOCKSIZE, ROUNDS> {
    pub fn message_hash<R: BufRead>(
        &mut self,
        message_length: u64,
        mut reader: R,
    ) -> Result<(), std::io::Error>
    where
        T: Default,
        T: Copy,
        T: Modular<T>,
        T: LowerHex,
    {
        let mut last_bytes_read = 0usize;

        loop {
            match reader.read(&mut self.block) {
                Ok(bytes_read) => {
                    // EOF: save last file address to restart from this address for next run
                    if bytes_read == 0 {
                        // the message is a multiple of BLOCKSIZE. It still need to be padded
                        if last_bytes_read == BLOCKSIZE {
                            let _ = self.block_padding(0, message_length);
                            self.block_hash();
                        }

                        break;
                    }

                    last_bytes_read = bytes_read;

                    // if bytes_read is exactly BLOCKSIZE, still need to hash
                    if bytes_read == BLOCKSIZE {
                        self.block_hash();
                    // padd buffer if block size is < BLOCKSIZE
                    } else if bytes_read < BLOCKSIZE {
                        // padd buffer if block size is < BLOCKSIZE
                        let additional_block = self.block_padding(bytes_read, message_length);

                        // anyway, hash the last or before last block
                        self.block_hash();

                        // if an additional block is created, use it
                        if let Some(new_block) = additional_block {
                            self.block = new_block;
                            self.block_hash();
                        }
                    } else {
                        panic!("bytes_read > BLOCKSIZE which shouldn't occur");
                    }
                }
                Err(err) => {
                    return Err(err);
                }
            };
        }

        Ok(())
    }

    fn message_schedule(&self) -> [T; ROUNDS]
    where
        T: Default,
        T: Copy,
        T: Modular<T>,
        T: LowerHex,
    {
        // these are W1 to W64
        let mut w = [T::default(); ROUNDS];

        // get the u32 or u64 integer bit size to split the block into chunks
        let size = std::mem::size_of::<T>();

        // get a 'window' of 4 or 8 bytes each
        let mut iter = self.block.chunks(size);

        // first 16 words are the same
        for i in 0..16 {
            w[i] = T::to_uint(iter.next().unwrap());
        }

        // remaining words are given by a formula
        for i in 16..ROUNDS {
            let s1 = w[i - 7].add_modulo((self.scramble_funcs.sigma1)(w[i - 2]));
            let s2 = s1.add_modulo((self.scramble_funcs.sigma0)(w[i - 15]));
            //w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
            w[i] = s2.add_modulo(w[i - 16]);
        }

        // for i in 0..N {
        //     print!("w[{}]={:0x} ", i, w[i]);
        // }
        w
    }

    // a round of sha256 calculation
    pub fn block_hash(&mut self)
    where
        T: Default,
        T: Copy,
        T: Modular<T>,
        T: LowerHex,
    {
        // decompose block
        let W = self.message_schedule();

        // build tmp variables
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            self.hash[0],
            self.hash[1],
            self.hash[2],
            self.hash[3],
            self.hash[4],
            self.hash[5],
            self.hash[6],
            self.hash[7],
        );

        // 64 rounds
        for i in 0..ROUNDS {
            let s1 = h.add_modulo((self.scramble_funcs.SIGMA1)(e));
            let s2 = s1.add_modulo((self.scramble_funcs.ch)(e, f, g));
            let s3 = s2.add_modulo(self.k_constants[i]);
            let T1 = s3.add_modulo(W[i]);
            //let T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];

            let T2 = (self.scramble_funcs.SIGMA0)(a).add_modulo((self.scramble_funcs.maj)(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.add_modulo(T1);
            d = c;
            c = b;
            b = a;
            a = T1.add_modulo(T2);
            // println!(
            //     "{:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} ",
            //     a, b, c, d, e, f, g, h
            // );
        }

        // reallocate H
        self.hash[0] = self.hash[0].add_modulo(a);
        self.hash[1] = self.hash[1].add_modulo(b);
        self.hash[2] = self.hash[2].add_modulo(c);
        self.hash[3] = self.hash[3].add_modulo(d);
        self.hash[4] = self.hash[4].add_modulo(e);
        self.hash[5] = self.hash[5].add_modulo(f);
        self.hash[6] = self.hash[6].add_modulo(g);
        self.hash[7] = self.hash[7].add_modulo(h);
    }

    // pad block
    pub fn block_padding(&mut self, bytes_read: usize, length: u64) -> Option<[u8; BLOCKSIZE]> {
        debug_assert!(bytes_read <= BLOCKSIZE);

        // message length should be in bits
        let message_length = length * 8;

        // this will be added at the end of the message
        let length_as_bytes = message_length.to_be_bytes();

        // either 56 for 512-bit block size (SHA224/256), or 112 for 1024-bit block size (SHA384/512)
        let lower_bound = BLOCKSIZE - BLOCKSIZE / 8;

        // either 64 or 128
        let higher_bound = BLOCKSIZE;

        // in any case, there's enough space to add 0b10000000 (0x80)
        self.block[bytes_read] = 0x80;

        // how many bits to add depends on how enough room is left to let the 64-bit or 128-bit length
        // representation
        if bytes_read < lower_bound {
            for i in bytes_read + 1..higher_bound {
                self.block[i] = 0;
            }
            self.block[higher_bound - 8..higher_bound].clone_from_slice(&length_as_bytes);
            None
        } else {
            for i in bytes_read + 1..higher_bound {
                self.block[i] = 0;
            }
            let mut additional_block = [0u8; BLOCKSIZE];
            additional_block[higher_bound - 8..higher_bound].clone_from_slice(&length_as_bytes);
            Some(additional_block)
        }
    }

    // reset block values
    #[allow(dead_code)]
    pub fn clear(&mut self)
    where
        T: Default,
        T: Copy,
    {
        self.hash = [T::default(); 8];
    }
}

// print out final hash
impl<T, const BLOCKSIZE: usize, const ROUNDS: usize> Display for Hash<T, BLOCKSIZE, ROUNDS>
where
    T: LowerHex,
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut h = String::with_capacity(std::mem::size_of::<T>());
        for i in 0..8 {
            h.push_str(&format!(
                "{0:0width$x}",
                self.hash[i],
                width = 2 * std::mem::size_of::<T>()
            ));
        }
        write!(f, "{}", h)
    }
}

#[cfg(test)]
mod tests {
    use crate::sha256::Sha256;

    #[test]
    fn display() {
        // the initial IV
        let block: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // convert it to a block of u8
        let mut v = Vec::with_capacity(32);
        for u32_int in &block {
            let buf = u32_int.to_le_bytes();
            v.push(buf);
        }

        // print out hash and verify
        let mut h = Sha256::new();

        assert_eq!(
            h.to_string(),
            "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"
        );

        // full of zeros
        h.hash = [0u32; 8];
        assert_eq!(
            h.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
