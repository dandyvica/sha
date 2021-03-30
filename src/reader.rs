use std::fmt::{Display, LowerHex};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
//use std::path::PathBuf;

use crate::convert::Modular;
use crate::sha::Hash;
use crate::sha256::Sha256;

// Reuse the same String buffer
pub fn hash_reader<'a, T, R: BufRead, const BLOCKSIZE: usize, const ROUNDS: usize>(
    message_length: u64,
    mut reader: R,
    hash: &'a mut Hash<T, BLOCKSIZE, ROUNDS>,
) -> Result<&'a mut Hash<T, BLOCKSIZE, ROUNDS>, std::io::Error>
where
    T: Default,
    T: Copy,
    T: Modular<T>,
    T: LowerHex,
{
    // define buffer
    //let mut block = [0; BLOCKSIZE];

    //let mut handle = file.take(blocksize as u64);

    // uses a reader buffer
    //let mut reader = BufReader::new(file);
    // let mut line = String::new();

    // set initialization vector
    //let mut hash = Hash256::initialization_vector();

    loop {
        match reader.read(&mut hash.block) {
            Ok(bytes_read) => {
                // EOF: save last file address to restart from this address for next run
                if bytes_read == 0 {
                    println!("byes_read={}", bytes_read);
                    break;
                }
                println!("bytes_read={}", bytes_read);

                // if bytes_read is exactly BLOCKSIZE, still need to hash
                if bytes_read == BLOCKSIZE {
                    hash.block_hash();
                // padd buffer if block size is < BLOCKSIZE
                } else if bytes_read < BLOCKSIZE {
                    // padd buffer if block size is < BLOCKSIZE
                    let additional_block = hash.block_padding(bytes_read, message_length);
                    match additional_block {
                        None => {
                            hash.block_hash();
                            break;
                        }
                        Some(new_block) => {
                            hash.block_hash();
                            hash.block_hash();
                            break;
                        }
                    };
                } else {
                    panic!("bytes_read > BLOCKSIZE which shouldn't occur");
                }
            }
            Err(err) => {
                println!("error={:?}", err);
                return Err(err);
            }
        };
    }

    Ok(hash)
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::sha256::Sha256;
//     use std::io::Cursor;

//     #[test]
//     fn test_vector_1() {
//         let msg = b"abc";
//         let mut cursor = Cursor::new(msg);
//         let reader = BufReader::new(cursor);
//         let mut hash = Hash::<u32>::new();

//         let h = hash_reader::<u32, std::io::BufReader<Cursor<&[u8; 3]>>, 64>(
//             msg.len() as u64,
//             reader,
//             &mut hash,
//         );
//         assert_eq!(
//             h.unwrap().to_string(),
//             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
//         );
//     }

//     #[test]
//     fn test_vector_2() {
//         let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
//         let mut cursor = Cursor::new(msg);
//         let reader = BufReader::new(cursor);
//         let mut hash = Hash::<u32>::new();

//         let h = hash_reader::<u32, std::io::BufReader<Cursor<&[u8; 56]>>, 64>(
//             msg.len() as u64,
//             reader,
//             &mut hash,
//         );
//         assert_eq!(
//             h.unwrap().to_string(),
//             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
//         );
//     }

//     #[test]
//     fn test_vector_3() {
//         let msg = &[b'a'; 1_000_000];
//         let mut cursor = Cursor::new(msg);
//         let reader = BufReader::new(cursor);
//         let mut hash = Hash::<u32>::new();

//         let h = hash_reader::<u32, std::io::BufReader<Cursor<&[u8; 1_000_000]>>, 64>(
//             msg.len() as u64,
//             reader,
//             &mut hash,
//         );
//         assert_eq!(
//             h.unwrap().to_string(),
//             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
//         );
//     }
// }
