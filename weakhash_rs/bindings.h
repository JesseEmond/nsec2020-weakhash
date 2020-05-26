// Would have liked to use existing DES package, but OpenSSL wrappers
// don't seem to include DES (insecure anyway), and 'des' package I
// found has a DES implementation that can encrypt a u64 directly
// (yay!), but is private to the package. It only exposes an interface
// that deals with multiple blocks, which we don't need (and would
// potentially be needlessly slow?). Using this as an oppurtunity to
// learn about using C in Rust.
#include <openssl/des.h>