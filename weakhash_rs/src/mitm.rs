use std::convert::TryInto;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use super::des;

type BlockHash = u32;

const LOOKUP_BITS: u32 = 31;
const LOOKUP_SIZE: BlockHash = 1 << LOOKUP_BITS;

pub struct Collision {
    pub encryption_key: u64,
    pub decryption_key: u64,
    pub output: u64,  // To know which of the target hash matched
}

pub fn encrypt_iv(key: u64) -> u64 {
    let iv: u64 = u64::from_be_bytes(*b"weakhash");
    des::encrypt(key, iv)
}

pub fn counter_to_key(counter: u64) -> u64 {
    const INPUT_BYTE_MASK: u64 = 0b1111111;
    // "Expand" sequences of 7-bits to 8-bits, with last bit set to 0
    // (ignored in DES keys). Supports inputs up to 56-bits.
    assert!(counter < (1 << 56));
    let mut key: u64 = 0;
    for i in 0..(56/7) {
        let input_shift = i * 7;
        let input_mask = INPUT_BYTE_MASK << input_shift;
        let input_byte = (counter & input_mask) >> input_shift;
        assert!(input_byte < 0x0b10000000);
        let output_byte = input_byte << 1;
        let output_shift = i * 8;
        key |= output_byte << output_shift;
    }
    key
}

pub fn hash_block(block: u64) -> BlockHash {
    const HASH_MASK: u64 = (1 << LOOKUP_BITS) - 1;
    return (block & HASH_MASK).try_into().unwrap();
}

pub fn build_lookup_table(show_progress_every: u32) -> Vec<BlockHash> {
    println!("[*] Initializing lookup table...");
    let mut lookup = vec![0; LOOKUP_SIZE.try_into().unwrap()];
    println!("[*] Building mitm lookup table...");
    let start = Instant::now();
    for counter in 0..LOOKUP_SIZE {
        let key = counter_to_key(counter as u64);
        let block = encrypt_iv(key);
        let index: usize = hash_block(block).try_into().unwrap();
        lookup[index] = counter;

        if counter > 0 && counter % show_progress_every == 0 {
            show_table_build_progress(counter, start);
        }
    }
    lookup
}

fn show_table_build_progress(counter: u32, start_time: Instant) {
    let total = LOOKUP_SIZE as f64;
    let processed: f64 = counter as f64;
    let remaining = total - processed;
    let percent: f64 = processed / total * 100f64;
    let seconds: f64 = start_time.elapsed().as_secs_f64();
    let speed = processed / seconds;
    let time_left = remaining / speed;
    println!("    processed {} out of {} ({:.2}%) {:.2}/s ~{:.2}s left",
             counter, LOOKUP_SIZE, percent, speed, time_left);
}

fn search_collision_in_range(lookup: &Arc<Vec<BlockHash>>,
    target: u64, start: u64, end: u64) -> Option<Collision> {
    for counter in start..end {
        let key = counter_to_key(counter);
        let block = des::decrypt(key, target);
        let index: usize = hash_block(block).try_into().unwrap();
        let enc_counter = lookup[index];
        let enc_key = counter_to_key(enc_counter as u64);
        if encrypt_iv(enc_key) == block {
            return Some(Collision {
                encryption_key: enc_key,
                decryption_key: key,
                output: target
            });
        }
    }
    None
}

pub fn find_collision(lookup: &Arc<Vec<BlockHash>>, targets: Vec<u64>,
    show_progress_every: u64, num_threads: u64) -> Collision {
    println!("[*] Finding a collision...");
    assert!(show_progress_every % num_threads == 0);
    let mut counter = 0u64;
    let start_time = Instant::now();
    let step = show_progress_every / num_threads;
    loop {
        let mut threads = vec![];
        for thread_i in 0..num_threads {
            let lookup = lookup.clone();
            let target = targets[thread_i as usize % targets.len()];
            threads.push(thread::spawn(move || {
                let start = counter + step * thread_i;
                let end = start + step;
                search_collision_in_range(&lookup, target, start, end)
            }));
        }
        for thread in threads {
            if let Some(collision) = thread.join().unwrap() {
                return collision;
            }
        }

        counter += show_progress_every;
        show_collision_progress(counter, start_time)
    }
}

fn show_collision_progress(counter: u64, start_time: Instant) {
    let seconds: f64 = start_time.elapsed().as_secs_f64();
    let speed = (counter as f64) / seconds;
    println!("    processed {} {:.2}/s", counter, speed);
}