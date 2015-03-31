#ifndef FUNTLS_AES_AES_H_INCLUDED
#define FUNTLS_AES_AES_H_INCLUDED

// FIPS PUB 197: ADVANCED ENCRYPTION STANDARD (AES)
// http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

// [AES] is a symmetric block cipher that can process data blocks of
// 128 bits, using cipher keys with lengths of 128, 192, and 256 bits.

#include <vector>
#include <cstdint>

namespace funtls { namespace aes {

std::vector<uint8_t> aes_128_ecb(const std::vector<uint8_t>& key, const std::vector<uint8_t>& input);

} } // namespace funtls::aes

#endif
