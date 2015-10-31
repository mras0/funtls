#include "chacha.h"
#include <array>
#include <string.h>
#include <util/test.h>

namespace funtls { namespace chacha {

using state = std::array<uint32_t, 16>;

constexpr uint32_t rol(uint32_t x, uint32_t n) {
    return (x<<n) | (x>>(32-n));
}

constexpr uint32_t ror(uint32_t x, uint32_t n) {
    return (x<<(32-n)) | (x>>n);
}

void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
   a += b; d ^= a; d = rol(d, 16);
   c += d; b ^= c; b = rol(b, 12);
   a += b; d ^= a; d = rol(d, 8);
   c += d; b ^= c; b = rol(b, 7);
}

inline uint32_t get_le_uint32(const uint8_t* b) {
    return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1])<<8) | (static_cast<uint32_t>(b[2])<<16) | (static_cast<uint32_t>(b[3])<<24);
}

inline void put_le_uint32(uint8_t* b, uint32_t n) {
    b[0] = static_cast<uint8_t>(n);
    b[1] = static_cast<uint8_t>(n>>8);
    b[2] = static_cast<uint8_t>(n>>16);
    b[3] = static_cast<uint8_t>(n>>24);
}

void initial_state(state& s, const uint8_t* key, const uint8_t* nonce, uint32_t block_count)
{
    // The first four words (0-3) are constants
    s[ 0] = 0x61707865;
    s[ 1] = 0x3320646e;
    s[ 2] = 0x79622d32;
    s[ 3] = 0x6b206574;
    // The next eight words (4-11) are taken from the 256-bit key by
    // reading the bytes in little-endian order, in 4-byte chunks.
    s[ 4] = get_le_uint32(&key[0*4]);
    s[ 5] = get_le_uint32(&key[1*4]);
    s[ 6] = get_le_uint32(&key[2*4]);
    s[ 7] = get_le_uint32(&key[3*4]);
    s[ 8] = get_le_uint32(&key[4*4]);
    s[ 9] = get_le_uint32(&key[5*4]);
    s[10] = get_le_uint32(&key[6*4]);
    s[11] = get_le_uint32(&key[7*4]);
    // Word 12 is a block counter
    s[12] = block_count;
    // Words 13-15 are a nonce, which should not be repeated for the same
    // key.  The 13th word is the first 32 bits of the input nonce taken
    // as a little-endian integer, while the 15th word is the last 32 bits.
    s[13] = get_le_uint32(&nonce[0*4]);
    s[14] = get_le_uint32(&nonce[1*4]);
    s[15] = get_le_uint32(&nonce[2*4]);
}

void block(state& s)
{
   //ChaCha20 runs 20 rounds, alternating between "column rounds" and
   //"diagonal rounds".  Each round consists of four quarter-rounds, and
   //they are run as follows.  Quarter rounds 1-4 are part of a "column"
   //round, while 5-8 are part of a "diagonal" round:

    const state initial = s;
    for (int i = 0; i < 10; ++i) {
        quarter_round(s[ 0], s[ 4], s[ 8], s[12]);
        quarter_round(s[ 1], s[ 5], s[ 9], s[13]);
        quarter_round(s[ 2], s[ 6], s[10], s[14]);
        quarter_round(s[ 3], s[ 7], s[11], s[15]);
        quarter_round(s[ 0], s[ 5], s[10], s[15]);
        quarter_round(s[ 1], s[ 6], s[11], s[12]);
        quarter_round(s[ 2], s[ 7], s[ 8], s[13]);
        quarter_round(s[ 3], s[ 4], s[ 9], s[14]);
    }

    // At the end of 20 rounds (or 10 iterations of the above list), we add
    // the original input words to the output words, and serialize the
    // result by sequencing the words one-by-one in little-endian order.

    for (int i = 0; i < 16; ++i) {
        s[i] += initial[i];
    }
}

// The inputs to ChaCha20 are:
// o  A 256-bit key, treated as a concatenation of eight 32-bit little-endian integers.
// o  A 96-bit nonce, treated as a concatenation of three 32-bit little-endian integers.
// o  A 32-bit block count parameter, treated as a 32-bit little-endian integer.
// The output is 64 random-looking bytes.
void chacha20_block(uint8_t* out, const uint8_t* key, const uint8_t* nonce, uint32_t block_count)
{
    state s;
    initial_state(s, key, nonce, block_count);
    block(s);
    for (auto x : s) {
        put_le_uint32(out, x);
        out += 4;
    }
}

std::vector<uint8_t> poly1305_key_gen(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce)
{
    FUNTLS_CHECK_BINARY(key.size(), ==, key_length_bytes, "Invalid key length. Must be 256 bits.");
    FUNTLS_CHECK_BINARY(nonce.size(), ==, nonce_length_bytes, "Invalid nonce length. Must be 96 bits.");

    std::vector<uint8_t> block(block_length_bytes);
    chacha20_block(block.data(), key.data(), nonce.data(), 0);
    block.resize(32);
    return block;
}

std::vector<uint8_t> chacha20(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& data)
{
    FUNTLS_CHECK_BINARY(key.size(), ==, key_length_bytes, "Invalid key length. Must be 256 bits.");
    FUNTLS_CHECK_BINARY(nonce.size(), ==, nonce_length_bytes, "Invalid nonce length. Must be 96 bits.");

    uint32_t block_count = 1;

    auto res = data;
    for (size_t i = 0; i < data.size(); i += block_length_bytes) {
        const size_t this_block = std::min(data.size() - i, block_length_bytes);
        uint8_t key_stream[block_length_bytes];
        chacha20_block(key_stream, key.data(), nonce.data(), block_count++);
        for (size_t j = 0; j < this_block; ++j) {
            res[i+j] ^= key_stream[j];
        }
    }
    return res;
}

} } // namespace funtls::chacha
