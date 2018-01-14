#![feature(integer_atomics)]

extern crate secp256k1;
extern crate rand;
extern crate tiny_keccak;

use secp256k1::Secp256k1;
use rand::{thread_rng, ThreadRng};
use tiny_keccak::Keccak;
use std::fmt::Write;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::io;

fn generate_key_address(rng: &mut ThreadRng, context: &Secp256k1) -> (String, String) {
    let (private_key, public_key) = context.generate_keypair(rng)
        .expect("Could not generate wallet keypair");

    let mut private_key_string = String::new();

    for &byte in private_key[..].iter() {
        write!(&mut private_key_string, "{:02x}", byte).expect("Unable to write");
    }

    let mut sha3 = Keccak::new_keccak256();
    sha3.update(&public_key.serialize_uncompressed()[1..65]);

    let mut address: [u8; 32] = [0; 32];
    sha3.finalize(&mut address);

    let mut address_string = String::new();
    for &byte in address.iter().skip(12) {
        write!(&mut address_string, "{:02x}", byte).expect("Unable to write");
    }

    (private_key_string, address_string)
}

fn find_address_starting_with(found: Arc<AtomicBool>, processed: Arc<AtomicU64>, x: &String)
        -> (String, String)
{
    let mut rng = thread_rng();
    let context = Secp256k1::new();

    loop {
        if found.load(Ordering::Relaxed) {
            return (String::new(), String::new());
        }
        let (pkey, address) = generate_key_address(&mut rng, &context);
        if address.starts_with(x) {
            return (pkey, address);
        }
        processed.fetch_add(1, Ordering::Relaxed);
    }
}

fn is_possible_pattern(x: &String) -> bool {
    x.as_bytes().iter().all(|&c| (c >= 'a' as u8 && c <= 'f' as u8)
        || (c >= '0' as u8 && c <= '9' as u8))
}

static THREADS_COUNT: u32 = 4;

fn main() {
    println!("Enter starting line for an address:");

    let mut pattern = String::new();
    io::stdin().read_line(&mut pattern).expect("Could not read pattern from stdin");
    pattern = String::from(pattern.trim());

    if !is_possible_pattern(&pattern) {
        println!("Impossible pattern. Use 0-9, a-f");
        return;
    }

    println!("Generating");

    let mut threads = vec![];
    let (tx, rx): (Sender<(String, String)>, Receiver<(String, String)>) = mpsc::channel();
    let found  = Arc::new(AtomicBool::new(false));
    let processed  = Arc::new(AtomicU64::new(0));

    for _ in 0..THREADS_COUNT {
        let thread_tx = tx.clone();
        let pattern_clone = pattern.clone();
        let found_clone = found.clone();
        let processed_clone = processed.clone();

        threads.push(thread::spawn(move || {
            thread_tx.send(find_address_starting_with(
                found_clone, processed_clone, &pattern_clone)
            ).expect("Could not send");
        }));
    }

    let start_time = Instant::now();
    loop {
        if let Ok((pkey, address)) = rx.recv_timeout(Duration::from_millis(1000)) {
            println!("Private key: {}", pkey);
            println!("Address: {}", address);
            break;
        }

        let elapsed = start_time.elapsed().as_secs();
        let processed_addresses = processed.load(Ordering::Relaxed);
        let speed = processed_addresses / elapsed;

        let difficulty = 16u64.pow(pattern.len() as u32);
        let estimated_time = difficulty / speed;
        println!("Speed: {} h/s. Work time: {}s. Estimated time: {}s",
                 speed, elapsed, estimated_time);
    }

    found.store(true, Ordering::Relaxed);

    for t in threads {
        let _ = t.join();
    }

}