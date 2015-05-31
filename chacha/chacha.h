#ifndef CHACHA_CHACHA_H_INCLUDED
#define CHACHA_CHACHA_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <vector>

// Implementation of ChaCha20 based on RFC7539
namespace funtls { namespace chacha {

constexpr size_t key_length_bytes   = 256 / 8;
constexpr size_t nonce_length_bytes = 96 / 8;
constexpr size_t block_length_bytes = 64;

std::vector<uint8_t> poly1305_key_gen(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce);
std::vector<uint8_t> chacha20(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& data);

} } // namespace funtls::chacha

#endif
