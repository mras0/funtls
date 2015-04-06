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

int main()
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
        // (ab)use the fact that DES = 3DES(k,k,k)
        FUNTLS_ASSERT_EQUAL(t.E, _3des::_3des_encrypt(t.K, t.K, t.K, t.M));
        FUNTLS_ASSERT_EQUAL(t.M, _3des::_3des_decrypt(t.K, t.K, t.K, t.E));
    }
}
