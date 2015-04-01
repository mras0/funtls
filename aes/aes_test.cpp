#include <iostream>

#include <aes/aes.h>
#include <util/base_conversion.h>
#include <util/test.h>

using namespace funtls;

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& v)
{
    return os << funtls::util::base16_encode(v);
}

int main()
{
    {
        // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf Appendix-B
        std::vector<uint8_t> input     {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
        std::vector<uint8_t> key       {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        std::vector<uint8_t> expeceted {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
        FUNTLS_ASSERT_EQUAL(expeceted, aes::aes_128_ecb(key, input));
    }

    // http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    // F.1.1 ECB-AES128.Encrypt
    // Key 2b7e151628aed2a6abf7158809cf4f3c
    const auto key   = util::base16_decode("2b7e151628aed2a6abf7158809cf4f3c");
    // Block #1
    // Plaintext 6bc1bee22e409f96e93d7e117393172a
    // Input Block 6bc1bee22e409f96e93d7e117393172a
    // Output Block 3ad77bb40d7a3660a89ecaf32466ef97
    // Ciphertext 3ad77bb40d7a3660a89ecaf32466ef97
    const auto input = util::base16_decode("6bc1bee22e409f96e93d7e117393172a");
    FUNTLS_ASSERT_EQUAL(util::base16_decode("3ad77bb40d7a3660a89ecaf32466ef97"), aes::aes_128_ecb(key, input));
    // Block #2
    // Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
    // Input Block ae2d8a571e03ac9c9eb76fac45af8e51
    // Output Block f5d3d58503b9699de785895a96fdbaaf
    // Ciphertext f5d3d58503b9699de785895a96fdbaaf
    // Block #3
    // Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
    // Input Block 30c81c46a35ce411e5fbc1191a0a52ef
    // Output Block 43b1cd7f598ece23881b00e3ed030688
    // Ciphertext 43b1cd7f598ece23881b00e3ed030688
    // Block #4
    // Plaintext f69f2445df4f9b17ad2b417be66c3710
    // Input Block f69f2445df4f9b17ad2b417be66c3710
    // Output Block 7b0c785e27e8ad3f8223207104725dd4
    // Ciphertext 7b0c785e27e8ad3f8223207104725dd4
}
