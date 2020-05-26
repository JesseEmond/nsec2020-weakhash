use criterion::{black_box, criterion_group, criterion_main, Criterion};

use weakhash_rs::{des, mitm};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("encrypt", |b| b.iter(|| {
    	let key = black_box(0x1337);
    	let plaintext = u64::from_be_bytes(*b"weakhash");
    	des::encrypt(key, plaintext)
    }));

    c.bench_function("decrypt", |b| b.iter(|| {
    	let key = black_box(0x1337);
    	let ciphertext = 0x32da4c17852dbcdcu64;
    	des::decrypt(key, ciphertext)
    }));

    c.bench_function("counter_to_key",
    	|b| b.iter(|| mitm::counter_to_key(black_box(0xda4c17852dbcdcu64))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);