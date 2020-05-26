// clang++ -O2 -std=c++17 -lcrypto -lssl -pthread weakhash.cpp -o weakhash && ./weakhash
// Speeds achieved on my machine:
//   Building lookup table: 3.9m/s
// Searching for collision: 9.7m/s
#include <openssl/des.h>
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <random>
#include <cstring>
#include <unordered_set>
#include <array>
#include <list>
#include <iostream>
#include <climits>
#include <functional>
#include <thread>
#include <iomanip>
#include <future>

// I'm... not sure the way I'm using this is defined behavior..... Worth looking into.
union block_t {
  std::uint64_t u64;
  DES_cblock block;
};

// We store hashes as 32-bits. Block hashes are (block_t::u64 mod 2^something)
// to fit in RAM.
using block_hash_t = std::uint32_t;

using lookup_table_t = std::vector<block_hash_t>;
// 32-bits per lookup entry, can store ~8GB in my RAM.
// 8GB / 4bytes(int32) = 2147483648. That's 31 bits.
// Leaves us with a bruteforce of O(2^(64-31)) = O(2^33) ~= 8,589,934,592.
constexpr uint64_t LOOKUP_TABLE_BITS = 31;

struct Collision {
	block_t encrypting_key;
	block_t decrypting_key;
	block_t output; // to know which target collided
};
using maybe_collision_t = std::optional<Collision>;

// Usage:
// SpeedMeasurer speed;
// // ...
// speed.measure(items_processed);
// // ...
// cout << speed;
struct SpeedMeasurer {
	std::chrono::high_resolution_clock::time_point start;
	uint64_t items;
	SpeedMeasurer() : start{std::chrono::high_resolution_clock::now()}, items{0} {}
	void measure(uint64_t items_processed) { items += items_processed; }
	double items_per_second() const {
		const auto stop = std::chrono::high_resolution_clock::now();
		using seconds_t = std::chrono::duration<double, std::chrono::seconds::period>;
		const seconds_t seconds = stop - start;
		return static_cast<double>(items) / seconds.count();
	}
};
std::ostream& operator<<(std::ostream& os, const SpeedMeasurer& speed) {
	os << speed.items_per_second() << "/s";
	return os;
}


// NOTE: ALL RAW 64-BIT HEX VALUES ARE IN BIG-ENDIAN. MUST BE STORED IN LITTLE-ENDIAN!
constexpr uint64_t flip_endian(uint64_t x) {
	return __builtin_bswap64(x);
}

// Taken from the challenge directly.
void weakhash(uint8_t *dst, const char *src) {
	DES_key_schedule ks;
	DES_cblock key;
	DES_cblock data;
	size_t u, n;
	memcpy(data, "weakhash", 8);
	n = strlen(src);
	for (u = 0; u < n; u += 8) {
		size_t v;
		for (v = 0; v < 8; v ++) {
			if (u + v < n) {
				key[v] = ((unsigned char)src[u + v] << 1) + 2;
			} else {
				key[v] = 0;
			}
		}
		DES_set_key_unchecked(&key, &ks);
		DES_ecb_encrypt(&data, &data, &ks, 1);
	}
	memcpy(dst, data, 8);
}


block_t encrypt(block_t plaintext, block_t key) {
	DES_key_schedule ks;
    block_t output;
	DES_set_key_unchecked(&key.block, &ks);
	DES_ecb_encrypt(&plaintext.block, &output.block, &ks, 1);
	return output;
}


block_t decrypt(block_t ciphertext, block_t key) {
	DES_key_schedule ks;
    block_t output;
	DES_set_key_unchecked(&key.block, &ks);
	DES_ecb_encrypt(&ciphertext.block, &output.block, &ks, 0);
	return output;
}


// Takes an incremental counter and generates a DES key out of it,
// to where every last bit of each byte is 0 (not used by DES).
// Essentially expands each 7-bit sequence to be 8-bits (with 0 at
// end).
// Assumed to be < 2^56.
block_t counter_to_key(uint64_t n) {
	constexpr int INPUT_BYTES = 7;
	constexpr int INPUT_BYTE_BITS = 7;
	constexpr int BITS_MASK = (1 << INPUT_BYTE_BITS) - 1;
	constexpr int BYTE_BITS = 8;
	// We expand 7-bit bytes to 8-bits. No space for bits >= 56.
	assert(n < (1ULL << (INPUT_BYTES * BYTE_BITS)));
	uint64_t key = 0;
	for (uint64_t i = 0; i < INPUT_BYTES; ++i) {
		const uint64_t input_shift = i * INPUT_BYTE_BITS;
		const uint64_t byte_mask = BITS_MASK << input_shift;
		const uint64_t input_byte = (n & byte_mask) >> input_shift;
		const uint64_t output_byte = input_byte << 1; // ignore last bit
		const uint64_t output_shift = i * BYTE_BITS;
		key |= output_byte << output_shift;
	}
	return { .u64 = key };
}



block_hash_t block_hash(block_t block) {
	constexpr uint64_t mask = (1ULL << LOOKUP_TABLE_BITS) - 1;
	return block.u64 & mask;
}


block_t encrypt_iv_with_counter(const block_hash_t counter) {
	static const block_t weakhash_encoded = {
		.u64 = flip_endian(0x7765616B68617368ULL)
	};
	const block_t key = counter_to_key(counter);
	return encrypt(weakhash_encoded, key);
}


lookup_table_t build_lookup_table(const int show_progress_every) {
	std::cout << "[*] Initializing mitm lookup table..." << std::endl;
	// Init with zeros to spot hashes that are likely missing.
	constexpr uint64_t TABLE_SIZE = 1ULL << LOOKUP_TABLE_BITS;
 	lookup_table_t lookup(TABLE_SIZE, 0);

	std::cout << "[*] Building mitm lookup table..." << std::endl;
	
	// NOTE: could maybe be multithread, but fast enough to just wait a few mins.
	SpeedMeasurer speed;
	for (block_hash_t counter = 0; counter < TABLE_SIZE; ++counter) {
		const block_t enc = encrypt_iv_with_counter(counter);
		const block_hash_t hash = block_hash(enc);
		lookup.at(hash) = counter;
		if (counter > 0 && counter % show_progress_every == 0) {
			speed.measure(show_progress_every);
			const uint64_t items_left = TABLE_SIZE - counter;
			const double time_left = static_cast<double>(items_left) / speed.items_per_second();
			const double percent = static_cast<double>(counter) / TABLE_SIZE * 100.f;
			std::cout << "    processed " << counter << " out of " << TABLE_SIZE << " ("
					  << std::fixed << std::setprecision(2) << percent << "%) "
					  << speed << " ~" << time_left << "s left"
					  << std::endl;
		}
	}
	return lookup;
}


maybe_collision_t search_collision(const lookup_table_t& lookup, block_t target,
								   uint64_t start, uint64_t steps) {
	for (uint64_t counter = start; counter < start + steps; ++counter) {
		const block_t key = counter_to_key(counter);
		const block_t dec = decrypt(target, key);
		const block_hash_t hash = block_hash(dec);
		const block_hash_t collision_counter = lookup.at(hash);
		const block_t enc = encrypt_iv_with_counter(collision_counter);
		if (enc.u64 == dec.u64) {
			return Collision{
				.encrypting_key = counter_to_key(collision_counter),
				.decrypting_key = key,
				.output = target
			};
		}
	}
	return {};
}


Collision find_collision(const lookup_table_t& lookup, const std::vector<block_t>& targets,
						 const int num_threads, const int show_progress_every) {
	const uint64_t steps = show_progress_every / num_threads;
	std::cout << "[*] Finding a collision..." << std::endl;
	uint64_t counter = 0;
	std::optional<Collision> collision = {};
	while (!collision.has_value()) {
		SpeedMeasurer speed;
		std::vector<std::future<maybe_collision_t>> threads;
		for (int thread = 0; thread < num_threads; ++thread) {
			block_t target = targets[thread % targets.size()];
			threads.push_back(std::async(std::launch::async,
				search_collision, std::cref(lookup), target, counter, steps));
			counter += steps;
			speed.measure(steps);
		}
		for (auto& thread : threads) {
			const maybe_collision_t thread_collision = thread.get();
			if (thread_collision.has_value()) {
				collision = thread_collision;
			}
		}
		std::cout << "    processed " << counter << " " << speed << std::endl;
	}
	std::cout << "   found!" << std::endl;
	return *collision;
}


void run_tests() {
	uint8_t dst[8];
	weakhash(dst, "Hello World");
	const uint8_t expected[8] = {0xF3, 0x15, 0x06, 0x47, 0x12, 0x20, 0xCD, 0x8F};
	assert(std::equal(dst, dst+8, expected));
	
	block_t m = { .u64 = flip_endian(0x68656c6c6f796f75ULL) };
	block_t k = { .u64 = flip_endian(0x011F011F010E010EULL) };
	assert(encrypt(m, k).u64 == flip_endian(0x11191c3c353782bfULL));

	assert(counter_to_key(0x1FF).u64 == 0b11011111110);

	// Found from running this binary and finding a collision:
	const char* password =
		"\x2e\x01\x09\x78\x02\x7f\x7f\x7f\x53\x47\x0f\x50\x7f\x7f\x7f\x7f";
	uint8_t dst2[8];
	weakhash(dst2, password);
	const uint8_t expected2[8] = {0xDA, 0x99, 0xD1, 0xEA,
		                         0x64, 0x14, 0x4F, 0x3E};
	assert(std::equal(dst2, dst2+8, expected2));
}


int main() {
	run_tests();

	const lookup_table_t lookup = build_lookup_table(/*show_progress_every=*/10000000);
	const std::vector<block_t> targets = {
		{ .u64 = flip_endian(0xDA99D1EA64144F3EULL) },
		{ .u64 = flip_endian(0x59A3442D8BABCF84ULL) }
	};

	const Collision collision = find_collision(lookup, targets,
	                                           /*num_threads=*/5,
											   /*show_progress_every=*/50000000);

	std::cout << "COLLISION!" << std::endl;
	std::cout << "Encrypting (encoded) 'weakhash' with key "
			  << std::hex << flip_endian(collision.encrypting_key.u64)
			  << " then decrypting with key "
			  << std::hex << flip_endian(collision.decrypting_key.u64)
			  << " gives "
			  << std::hex << flip_endian(collision.output.u64)
			  << std::endl;

	return 0;
}