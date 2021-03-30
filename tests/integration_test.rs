use std::fs::File;
use std::io::Cursor;
use std::io::{BufRead, BufReader};

extern crate sha;
use crate::sha::sha256::Sha256;
use crate::sha::sha512::Sha512;

#[derive(Debug)]
struct TestCase {
    message: Vec<u8>,
    md: String,
}

// just return the trimmed string after = sign
fn strip(text: &str) -> String {
    let s: String = text.split('=').skip(1).collect();
    s.trim().to_string()
}

// reads the response file
fn read_rsp_file(response_file: &str) -> Vec<TestCase> {
    let mut tc: Vec<TestCase> = Vec::new();
    let mut msg = Vec::new();
    let mut message_length: usize = 0;

    let file = File::open(response_file).expect("file not found!");
    let reader = BufReader::new(file);

    for (n, s) in reader.lines().enumerate() {
        let line = s.unwrap();
        println!("n={}, line=<{}>", n + 1, line);

        // grab length
        if line.starts_with("Len =") {
            let l = strip(&line);
            message_length = usize::from_str_radix(&l, 10).expect("unable to convert to usize");

            // len is expressed in bytes
            assert_eq!(message_length % 8, 0);
            continue;
        }

        // grab the message and convert it to u8
        if line.starts_with("Msg =") && message_length != 0 {
            let bytes = strip(&line);
            assert_eq!(bytes.len(), 2 * message_length / 8);

            // convert string to Vec<u8>
            msg = bytes
                .as_bytes()
                .chunks(2)
                .map(std::str::from_utf8)
                .map(|x| u8::from_str_radix(x.unwrap(), 16).unwrap())
                .collect();
            continue;
        }

        // grab the hash
        if line.starts_with("MD =") && message_length != 0 {
            let hash = strip(&line);
            tc.push(TestCase {
                message: msg.clone(),
                md: hash.trim().to_string(),
            });
            msg.clear();
            continue;
        }
    }
    println!("end");

    tc
}

fn test_sha256(response_file: &str) {
    let tc = read_rsp_file(response_file);
    for x in &tc {
        let mut sha256 = Sha256::new();
        let cursor = Cursor::new(x.message.as_slice());
        let result = sha256.message_hash(x.message.len() as u64, cursor);
        assert!(result.is_ok());
        assert_eq!(sha256.to_string(), x.md);
    }
}
fn test_sha512(response_file: &str) {
    let tc = read_rsp_file(response_file);
    for x in &tc {
        let mut sha512 = Sha512::new();
        let cursor = Cursor::new(x.message.as_slice());
        let result = sha512.message_hash(x.message.len() as u64, cursor);
        assert!(result.is_ok());
        assert_eq!(sha512.to_string(), x.md);
    }
}

#[test]
fn all_sha() {
    test_sha256("tests/SHA256LongMsg.rsp");
    test_sha256("tests/SHA256ShortMsg.rsp");
    test_sha512("tests/SHA512LongMsg.rsp");
    test_sha512("tests/SHA512ShortMsg.rsp");
}
