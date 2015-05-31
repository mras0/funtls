#ifndef POLY1305_POLY1305_H_INCLUDED
#define POLY1305_POLY1305_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <vector>

// Implementation of Poly1305 based on RFC7539
namespace funtls { namespace poly1305 {

constexpr size_t key_length_bytes   = 32;
constexpr size_t block_length_bytes = 16;

std::vector<uint8_t> poly1305(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message);

} } // namespace funtls::poly1305

#endif
