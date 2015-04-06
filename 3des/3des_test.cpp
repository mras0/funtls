#include <iostream>
#include <cassert>

#include <3des/3des.h>
#include <util/base_conversion.h>
#include <util/test.h>

using namespace funtls;

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& v)
{
    return os << funtls::util::base16_encode(v);
}

void des_tests()
{
    static const struct {
        uint64_t K, M, E;
    } des_test_cases[] = {
        // Key                Message             Expected
        // Example from http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
        { 0x133457799BBCDFF1, 0x0123456789ABCDEF, 0x85E813540F0AB405 }, 
        // http://csrc.nist.gov/publications/nistpubs/800-20/800-20.pdf -- Appendix A
        { 0x0101010101010101, 0x8000000000000000, 0x95F8A5E5DD31D900 },
        { 0x8001010101010101, 0x0000000000000000, 0x95A8D72813DAA94D },
        { 0x7CA110454A1A6E57, 0x01A1D6D039776742, 0x690F5B0D9A26939B },
    };
    for (const auto& t : des_test_cases) {
        // (ab)use the fact that DES = 3DES(k,k,k) a.k.a Keying Option 3
        FUNTLS_ASSERT_EQUAL(t.E, _3des::_3des_encrypt(t.K, t.K, t.K, t.M));
        FUNTLS_ASSERT_EQUAL(t.M, _3des::_3des_decrypt(t.K, t.K, t.K, t.E));
    }
}

void _3des_tests()
{
    // http://csrc.nist.gov/publications/nistpubs/800-67-Rev1/SP-800-67-Rev1.pdf Appendix B
    const uint64_t K1 = 0x0123456789ABCDEF;
    const uint64_t K2 = 0x23456789ABCDEF01;
    const uint64_t K3 = 0x456789ABCDEF0123;

    const uint64_t M1 = 0x5468652071756663; // “The quic”
    const uint64_t M2 = 0x6B2062726F776E20; // “k brown ”
    const uint64_t M3 = 0x666F78206A756D70; // “fox jump

    const uint64_t C1 = 0xA826FD8CE53B855F;
    const uint64_t C2 = 0xCCE21C8112256FE6;
    const uint64_t C3 = 0x68D5C05DD9B6B900;

    FUNTLS_ASSERT_EQUAL(C1, _3des::_3des_encrypt(K1, K2, K3, M1));
    FUNTLS_ASSERT_EQUAL(M1, _3des::_3des_decrypt(K1, K2, K3, C1));
    FUNTLS_ASSERT_EQUAL(C2, _3des::_3des_encrypt(K1, K2, K3, M2));
    FUNTLS_ASSERT_EQUAL(M2, _3des::_3des_decrypt(K1, K2, K3, C2));
    FUNTLS_ASSERT_EQUAL(C3, _3des::_3des_encrypt(K1, K2, K3, M3));
    FUNTLS_ASSERT_EQUAL(M3, _3des::_3des_decrypt(K1, K2, K3, C3));
}

void _3des_cbc_simple()
{
    // Test 3DES-CBC
    // http://csrc.nist.gov/publications/nistpubs/800-20/800-20.pdf 5.2.1.1
    const auto key      = util::base16_decode("010101010101010101010101010101010101010101010101"); // K1=K2=K3
    const auto iv       = util::base16_decode("0000000000000000");

    static struct {
        char m[17];
        char e[17];
    } ts1[] = {
        { "8000000000000000", "95F8A5E5DD31D900" },
        { "4000000000000000", "DD7F121CA5015619" },
        { "2000000000000000", "2E8653104F3834EA" },
        { "1000000000000000", "4BD388FF6CD81D4F" },
        { "0800000000000000", "20B9E767B2FB1456" },
        { "0400000000000000", "55579380D77138EF" },
        { "0200000000000000", "6CC5DEFAAF04512F" },
        { "0100000000000000", "0D9F279BA5D87260" },
        { "0080000000000000", "D9031B0271BD5A0A" },
        { "0040000000000000", "424250B37C3DD951" },
        { "0020000000000000", "B8061B7ECD9A21E5" },
        { "0010000000000000", "F15D0F286B65BD28" },
        { "0008000000000000", "ADD0CC8D6E5DEBA1" },
        { "0004000000000000", "E6D5F82752AD63D1" },
        { "0002000000000000", "ECBFE3BD3F591A5E" },
        { "0001000000000000", "F356834379D165CD" },
        { "0000800000000000", "2B9F982F20037FA9" },
        { "0000400000000000", "889DE068A16F0BE6" },
        { "0000200000000000", "E19E275D846A1298" },
        { "0000100000000000", "329A8ED523D71AEC" },
        { "0000080000000000", "E7FCE22557D23C97" },
        { "0000040000000000", "12A9F5817FF2D65D" },
        { "0000020000000000", "A484C3AD38DC9C19" },
        { "0000010000000000", "FBE00A8A1EF8AD72" },
        { "0000008000000000", "750D079407521363" },
        { "0000004000000000", "64FEED9C724C2FAF" },
        { "0000002000000000", "F02B263B328E2B60" },
        { "0000001000000000", "9D64555A9A10B852" },
        { "0000000800000000", "D106FF0BED5255D7" },
        { "0000000400000000", "E1652C6B138C64A5" },
        { "0000000200000000", "E428581186EC8F46" },
        { "0000000100000000", "AEB5F5EDE22D1A36" },
        { "0000000080000000", "E943D7568AEC0C5C" },
        { "0000000040000000", "DF98C8276F54B04B" },
        { "0000000020000000", "B160E4680F6C696F" },
        { "0000000010000000", "FA0752B07D9C4AB8" },
        { "0000000008000000", "CA3A2B036DBC8502" },
        { "0000000004000000", "5E0905517BB59BCF" },
        { "0000000002000000", "814EEB3B91D90726" },
        { "0000000001000000", "4D49DB1532919C9F" },
        { "0000000000800000", "25EB5FC3F8CF0621" },
        { "0000000000400000", "AB6A20C0620D1C6F" },
        { "0000000000200000", "79E90DBC98F92CCA" },
        { "0000000000100000", "866ECEDD8072BB0E" },
        { "0000000000080000", "8B54536F2F3E64A8" },
        { "0000000000040000", "EA51D3975595B86B" },
        { "0000000000020000", "CAFFC6AC4542DE31" },
        { "0000000000010000", "8DD45A2DDF90796C" },
        { "0000000000008000", "1029D55E880EC2D0" },
        { "0000000000004000", "5D86CB23639DBEA9" },
        { "0000000000002000", "1D1CA853AE7C0C5F" },
        { "0000000000001000", "CE332329248F3228" },
        { "0000000000000800", "8405D1ABE24FB942" },
        { "0000000000000400", "E643D78090CA4207" },
        { "0000000000000200", "48221B9937748A23" },
        { "0000000000000100", "DD7C0BBD61FAFD54" },
        { "0000000000000080", "2FBC291A570DB5C4" },
        { "0000000000000040", "E07C30D7E4E26E12" },
        { "0000000000000020", "0953E2258E8E90A1" },
        { "0000000000000010", "5B711BC4CEEBF2EE" },
        { "0000000000000008", "CC083F1E6D9E85F6" },
        { "0000000000000004", "D2FD8867D50D2DFE" },
        { "0000000000000002", "06E7EA22CE92708F" },
        { "0000000000000001", "166B40B44ABA4BD6" }
    };

    for (const auto& t : ts1) {
        const auto input    = util::base16_decode(t.m);
        const auto expected = util::base16_decode(t.e);
        const auto encrypted = _3des::_3des_encrypt_cbc(key, iv, input);
        FUNTLS_ASSERT_EQUAL(expected, encrypted);
        FUNTLS_ASSERT_EQUAL(input, _3des::_3des_decrypt_cbc(key, iv, encrypted));
    }
}

void _3des_cbc_tests()
{
    _3des_cbc_simple();

    // test with randomly generated key, iv and input
    const auto key      = util::base16_decode("7a41cb315ba3a5be3f20e8de95e7937d2fa9e4257066a6ae");
    const auto iv       = util::base16_decode("c3d6e71e01b909a1");
    const auto input    = util::base16_decode("6b828909234864d806c32869df44cdd362ab3e97db69f9cb724e0587d93aad7274383dae41b8c8ba650f49a7cd2cd098");
    const auto expected = util::base16_decode("f5c3c4964492a142028230d3160edd2f622daa839ed11f26856882fdfb866f8f1c11f117f82513a1321a7adf64c8ec29");
    const auto encrypted = _3des::_3des_encrypt_cbc(key, iv, input);
    FUNTLS_ASSERT_EQUAL(expected, encrypted);
    FUNTLS_ASSERT_EQUAL(input, _3des::_3des_decrypt_cbc(key, iv, encrypted));
}

int main()
{
    des_tests();
    _3des_tests();
    _3des_cbc_tests();

}
