// Speeds achieved on my machine:
//   Building lookup table: 3.8m/s
// Searching for collision: 9.6m/s
// Eventually finds, after ~1,050,000,000 attempts:
// COLLISION!
// Encrypting 'weakhash' with A425CEC20 then with 6EECEC66A gives DA99D1EA64144F3E

use std::sync::Arc;

use weakhash_rs::mitm;

fn main() {
    let lookup = mitm::build_lookup_table(/*show_progress_every=*/10000000);
    let lookup = Arc::new(lookup);
    let targets = vec![0xDA99D1EA64144F3E, 0x59A3442D8BABCF84];
    let collision = mitm::find_collision(&lookup, targets,
        /*show_progress_every=*/50000000, /*num_threads=*/5);
    println!("COLLISION! Encrypting 'weakhash' with {:X} then with {:X} gives {:X}",
        collision.encryption_key, collision.decryption_key, collision.output);
}


#[cfg(test)]
mod tests {
    use super::*;
    use weakhash_rs::des;

    #[test]
    fn test_counter_to_key() {
        assert_eq!(mitm::counter_to_key(0x1FFu64), 0b110_11111110);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = u64::from_be_bytes(*b"weakhash");
        let key = 0x84BC0CF41Cu64;
        let ciphertext = des::encrypt(key, plaintext);
        assert_eq!(ciphertext, 0x4d8fd5d169e1ecb9u64);
        assert_eq!(des::decrypt(key, ciphertext), plaintext);
    }

    #[test]
    fn test_cpp_solution() {
        // Goal: find these via mitm :)
        // Values from C++ solution.
        let plaintext = u64::from_be_bytes(*b"weakhash");
        let key1 = 0x5e0414f206000000u64;
        let block = des::encrypt(key1, plaintext);
        assert_eq!(block, 0x32da4c17852dbcdcu64);
        let key2 = 0xa89020a200000000u64;
        assert_eq!(des::encrypt(key2, block), 0xda99d1ea64144f3eu64);
    }

    #[test]
    fn test_rust_solution() {
        // Based on:
        // Encrypting 'weakhash' with A425CEC20 then with 6EECEC66A gives DA99D1EA64144F3E
        let block = mitm::encrypt_iv(0xA425CEC20u64);
        assert_eq!(des::encrypt(0x6EECEC66Au64, block), 0xDA99D1EA64144F3Eu64);
    }
}