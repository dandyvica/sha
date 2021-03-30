use std::env;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;

mod convert;
mod scramble;
#[allow(non_upper_case_globals)]
mod sha;

mod sha256;
use sha256::Sha256;

mod sha512;
use sha512::Sha512;

#[derive(PartialEq)]
enum ShaVersion {
    Sha256,
    Sha512,
}

impl FromStr for ShaVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "256" => Ok(ShaVersion::Sha256),
            "512" => Ok(ShaVersion::Sha512),
            _ => unimplemented!("valid sha version is 256 or 512"),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // either 512 or 256
    let version = ShaVersion::from_str(&args[1]).unwrap();

    // create reader
    let file = File::open(&args[2]).expect(&format!("unable to open file {}", &args[2]));
    let reader = BufReader::new(file);

    // get file length
    let metadata = std::fs::metadata(&args[2])
        .expect(&format!("unable to get metadata for file {}", &args[2]));
    let file_length = metadata.len();

    // calculate hash
    if version == ShaVersion::Sha256 {
        let mut sha = Sha256::new();
        let _ = sha.message_hash(file_length, reader);
        println!("{}", sha);
    } else {
        let mut sha = Sha512::new();
        let _ = sha.message_hash(file_length, reader);
        println!("{}", sha);
    }
}
