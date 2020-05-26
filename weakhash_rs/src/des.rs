#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// Check 'bindings.h' to see why we're using C bindings over OpenSSL
// instead of libraries.
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));


pub fn encrypt(key: u64, plaintext: u64) -> u64 {
	let key = key.to_be_bytes();
	let plaintext = plaintext.to_be_bytes();
	let mut ciphertext = std::mem::MaybeUninit::uninit();
	let mut key_schedule = std::mem::MaybeUninit::uninit();
    let ciphertext: [u8; 8] = unsafe {
    	let mut key = key;
		DES_set_key_unchecked(&mut key, key_schedule.as_mut_ptr());
		let mut plaintext = plaintext;
		DES_ecb_encrypt(&mut plaintext, ciphertext.as_mut_ptr(),
						key_schedule.as_mut_ptr(), 1);
		ciphertext.assume_init()
	};
	return u64::from_be_bytes(ciphertext);
}

pub fn decrypt(key: u64, ciphertext: u64) -> u64 {
	let key = key.to_be_bytes();
	let ciphertext = ciphertext.to_be_bytes();
	let mut plaintext = std::mem::MaybeUninit::uninit();
	let mut key_schedule = std::mem::MaybeUninit::uninit();
    let plaintext: [u8; 8] = unsafe {
    	let mut key = key;
		DES_set_key_unchecked(&mut key, key_schedule.as_mut_ptr());
		let mut ciphertext = ciphertext;
		DES_ecb_encrypt(&mut ciphertext, plaintext.as_mut_ptr(),
						key_schedule.as_mut_ptr(), 0);
		plaintext.assume_init()
	};
	return u64::from_be_bytes(plaintext);
}