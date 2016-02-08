extern crate crypto;
extern crate argparse;

use argparse::ArgumentParser;
use argparse::Store;
use argparse::List;
use argparse::Print;

use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;
use crypto::sha2::Sha224;
use crypto::sha2::Sha256;
use crypto::sha2::Sha384;
use crypto::sha2::Sha512;
use crypto::sha2::Sha512Trunc224;
use crypto::sha2::Sha512Trunc256;
use crypto::blake2b::Blake2b;
use crypto::ripemd160::Ripemd160;
use crypto::whirlpool::Whirlpool;

use std::process;
use std::io::Error;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    let mut file_list = vec![]; 
    let mut algorithm = "md5".to_string();
    
    // Argument/Option parsing
    { 
        let mut parser = ArgumentParser::new();
        parser.set_description("Tool to calculate message digest of input file(s)");    
        parser.refer(&mut algorithm)
            .add_option(&["-a", "--algorithm"], Store,
            "Algorithm to use (default: md5)")
            .metavar("ALG");
        parser.refer(&mut file_list)
            .add_argument("FILENAME", List,
            "File(s) to hash")
            .required();
        parser.add_option(&["-V", "--version"],
            Print(env!("CARGO_PKG_VERSION").to_string()), "Show version");
        parser.parse_args_or_exit();
    }
    
    process_hash(file_list, &algorithm);
}

fn process_hash(file_list: Vec<String>, alg: &str) {
    let valid_algorithms: Vec<&str> =
        vec!["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512224",
             "sha512256", "blake2b-64", "ripemd160", "whirlpool"];
    let mut hasher: Box<Digest>;
    match alg {
        "md5" => { hasher = Box::new(Md5::new()) }
        "sha1" => { hasher = Box::new(Sha1::new()) }
        "sha224" => { hasher = Box::new(Sha224::new()) }
        "sha256" => { hasher = Box::new(Sha256::new()) }
        "sha384" => { hasher = Box::new(Sha384::new()) }
        "sha512" => { hasher = Box::new(Sha512::new()) }
        "sha512224" => { hasher = Box::new(Sha512Trunc224::new()) }
        "sha512256" => { hasher = Box::new(Sha512Trunc256::new()) }
        "blake2b-64" => { hasher = Box::new(Blake2b::new(64)) }
        "ripemd160" => { hasher = Box::new(Ripemd160::new()) }
        "whirlpool" => { hasher = Box::new(Whirlpool::new()) }
        _ => { println!("Algorithm not implemented");
               println!("Valid choices: {}", valid_algorithms.join(" "));
               process::exit(1); }
    }
    hash_file(file_list, &mut *hasher).unwrap();
}

fn hash_file(file_list: Vec<String>, hasher: &mut Digest) -> Result<(), Error> {
    const BUFF_SIZE: usize = 100;
    
    for file in &file_list {
        hasher.reset();
    	let mut f = try!(File::open(file));
    	let mut buffer = [0; BUFF_SIZE];
    
    	while let Ok(bytes_read) = f.read(&mut buffer[..]) {
            if bytes_read == 0 { break; }
            hasher.input(&buffer[..bytes_read]);
    	}

    	let out_str = hasher.result_str();
    	println!("{}  {}", out_str, file);
    }
    	Ok(())
}
