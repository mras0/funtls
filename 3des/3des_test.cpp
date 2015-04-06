#include <iostream>
#include <cassert>

#include <3des/3des.h>
#include <util/base_conversion.h>
#include <util/test.h>

namespace {
#include "3des_impl.cpp"
}

using namespace funtls;

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& v)
{
    return os << funtls::util::base16_encode(v);
}


#if 0
#define AES_CBC_TEST()                                                         \
    do {                                                                       \
        const auto _encrypted = 3des::3des_encrypt_cbc(key, iv, input);          \
        FUNTLS_ASSERT_EQUAL(expected, _encrypted);                             \
        FUNTLS_ASSERT_EQUAL(input, 3des::3des_decrypt_cbc(key, iv, _encrypted)); \
    } while (0)

//FUNTLS_ASSERT_EQUAL(input, 3des::3des_decrypt_ecb(key, _encrypted));


void test_cbc_3des128() // F.2.1
{
    const auto key      = util::base16_decode("2b7e151628aed2a6abf7158809cf4f3c");
    const auto iv       = util::base16_decode("000102030405060708090a0b0c0d0e0f");
    const auto input    = util::base16_decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    const auto expected = util::base16_decode(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");

    AES_CBC_TEST();
}
#endif

int main()
{
    FUNTLS_ASSERT_EQUAL(0x0102030405060708, inverse_initial_permute(initial_permute(0x0102030405060708)));

    // Example from http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
    const uint64_t K = 0x133457799BBCDFF1;
    const uint64_t M = 0x0123456789ABCDEF;

    std::cout << "K = 0x" << util::base16_encode(&K, sizeof(K)) << std::endl;
    std::cout << "M = 0x" << util::base16_encode(&M, sizeof(M)) << std::endl;
    std::cout << std::hex << des(K, M) << std::endl;
    FUNTLS_ASSERT_EQUAL(0x85E813540F0AB405, des(K,M));
    // http://csrc.nist.gov/publications/nistpubs/800-20/800-20.pdf -- Appendix A
}
