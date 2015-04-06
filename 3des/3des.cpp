#include <3des/3des.h>
#include <util/test.h>
#include <cassert>

#include <iostream> // TEMP

namespace {
#include "3des_impl.cpp"
}

namespace funtls { namespace _3des {

// Each DES key is nominally stored or transmitted as 8 bytes, each of odd parity
std::vector<uint8_t> _3des_encrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(key.size(), ==, key_length_bytes, "Invalid 3DES key length");
    FUNTLS_CHECK_BINARY(iv.size(),  ==, block_length_bytes, "Invalid 3DES initialization vector length");
    FUNTLS_CHECK_BINARY(input.size() % block_length_bytes, ==, 0,  "Invalid 3DES input length " + std::to_string(input.size()));
    return {};
}

std::vector<uint8_t> _3des_decrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(key.size(), ==, key_length_bytes, "Invalid 3DES key length");
    FUNTLS_CHECK_BINARY(iv.size(),  ==, block_length_bytes, "Invalid 3DES initialization vector length");
    FUNTLS_CHECK_BINARY(input.size() % block_length_bytes, ==, 0,  "Invalid 3DES input length " + std::to_string(input.size()));
    return {};
}

} } // namespace funtls::_3des
