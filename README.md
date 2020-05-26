# NSEC2020 - WeakHash
We did not solve this challenge during the competition. We took the wrong approach of assuming that
the reduced keyspace would impact the collision space (it does not necessarily).

After hearing from the challenge designer, this was meant to be solved as a traditional meet-in-the-middle
attack on 2-DES. They mention using 8GB RAM and ~4 hours to solve. After the competition, I adjusted my C++
code to solve the solution with the new hints.

The author also mentioned a clever trick to store twice as many blocks before searching for collisions:
Define a function `f` to expand an incremental counter (e.g. 32-bits when crafting a 31-bits table) into
a 64-bit key. I wrote a function that expands integers of up to 56-bits to 64-bits, by "expanding"
sequences of 7-bits to 8-bits (0 least significant bit, since DES ignore these in keys). Then, you can do
the following (pseudocode):

```
# Build 31-bits lookup table.
lookup = [0] * 2**31  # holding 32-bits ints
for counter in range(2**31):
  enc_key = f(counter)
  block = E(enc_key, b'weakhash')
  lookup[block & MASK_31_BITS] = counter

# Search for a collision.
for counter in range(2**56):
  dec_key = f(counter)
  block = D(dec_key, target_hash)
  enc_counter = lookup[block & MASK_31_BITS]
  enc_key = f(enc_counter)
  if E(enc_key, b'weakhash') == block:
    print("COLLISION! 'weakhash' encrypted with %s then %s gives %s",
          enc_key, dec_key, target)
```

I implemented this out of curiosity. `weakhash.cpp` has the information about the runtime speeds.
While implementing it, I got segfaults from how I was passing my lookup table to the threads
(needed a std::cref). This was painful to debug (and I can't imagine dealing with that *during* a CTF).

This lead me to want to try reimplementing this in Rust as a learning experience, with the same features
(multithreaded search with a 2^31 table). I included this in the repository as well.
