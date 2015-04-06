#ifndef FUNTLS_3DES_3DES_H_INCLUDED
#define FUNTLS_3DES_3DES_H_INCLUDED

#include <cstdint>
#include <vector>

// 3DES - http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf

namespace funtls { namespace _3des {
static constexpr uint8_t key_length_bytes    = 192/8;
static constexpr uint8_t block_length_bytes  = 64/8;

uint64_t _3des_encrypt(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t input);
uint64_t _3des_decrypt(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t input);

std::vector<uint8_t> _3des_encrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& input);
std::vector<uint8_t> _3des_decrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& input);
} } // namespace funtls::_3des


#endif
