#ifndef FUNTLS_AES_AES_H_INCLUDED
#define FUNTLS_AES_AES_H_INCLUDED

// FIPS PUB 197: ADVANCED ENCRYPTION STANDARD (AES)
// http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

// [AES] is a symmetric block cipher that can process data blocks of
// 128 bits, using cipher keys with lengths of 128, 192, and 256 bits.

#include <vector>
#include <cstdint>
#include <cstddef>

namespace funtls { namespace aes {

static constexpr unsigned block_size_bits  = 128;
static constexpr unsigned block_size_bytes = block_size_bits / 8;

std::vector<uint8_t> aes_encrypt_ecb(const std::vector<uint8_t>& key, const std::vector<uint8_t>& input);
std::vector<uint8_t> aes_decrypt_ecb(const std::vector<uint8_t>& key, const std::vector<uint8_t>& input);

std::vector<uint8_t> aes_encrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& input);
std::vector<uint8_t> aes_decrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& input);

// K:  secret key, whose length is appropriate for the underlying block cipher
// IV: initialization vector
// P:  plaintext
// A:  additional data
//
// returns C (cipher text), T (authentication tag)
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> aes_encrypt_gcm(const std::vector<uint8_t>& K, const std::vector<uint8_t>& IV, const std::vector<uint8_t>& P, const std::vector<uint8_t>& A);

std::vector<uint8_t> aes_decrypt_gcm(const std::vector<uint8_t>& K, const std::vector<uint8_t>& IV, const std::vector<uint8_t>& C, const std::vector<uint8_t>& A, const std::vector<uint8_t>& T);

void increment_be_number(uint8_t* n, size_t len);
} } // namespace funtls::aes

#endif
