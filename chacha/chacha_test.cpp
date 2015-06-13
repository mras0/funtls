#include <iostream>
#include <iomanip>
#include <string>
#include <util/base_conversion.h>
#include <util/test.h>
#include <array>

std::ostream& operator<<(std::ostream& os, const std::array<uint32_t, 16>& s);
#define TESTING_CHACHA
#include "chacha.cpp"

using namespace funtls;
using namespace funtls::chacha;

struct save_stream_state {
    save_stream_state(std::ostream& os) : os(os), state(nullptr) {
        state.copyfmt(os);
    }
    ~save_stream_state() {
        os.copyfmt(state);
    }
private:
    std::ostream& os;
    std::ios      state;
};

template<size_t ArraySize>
std::ostream& operator<<(std::ostream& os, const std::array<uint8_t, ArraySize>& s)
{
    return os << funtls::util::base16_encode(s.data(), s.size());
}

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& b)
{
    return os << util::base16_encode(b);
}

std::ostream& operator<<(std::ostream& os, const std::array<uint32_t, 16>& s)
{
    save_stream_state sss{os};

    os << std::hex << std::setfill('0');
    int i = 0;
    for (auto x : s) {
        os << std::setw(8) << x;
        if (++i % 4 == 0) os << std::endl;
        else os << " ";
    }

    return os;
}

void test_rotate()
{
    FUNTLS_ASSERT_EQUAL(0x00000000, rol(0x00000000, 1));
    FUNTLS_ASSERT_EQUAL(0x00000000, ror(0x00000000, 1));
    FUNTLS_ASSERT_EQUAL(0x00000002, rol(0x00000001, 1));
    FUNTLS_ASSERT_EQUAL(0x80000000, ror(0x00000001, 1));
    FUNTLS_ASSERT_EQUAL(0x00000001, rol(0x80000000, 1));
    FUNTLS_ASSERT_EQUAL(0x40000000, ror(0x80000000, 1));
    FUNTLS_ASSERT_EQUAL(0xcc5fed3c, rol(0x7998bfda, 7));
}

void test_quarter_round()
{
    static const struct {
        uint32_t ia, ib, ic, id;
        uint32_t oa, ob, oc, od;
    } tests[] = {
        {
            0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567,
            0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb,
        },
        {
            0x516461b1, 0x2a5f714c, 0x53372767, 0x3d631689,
            0xbdb886dc, 0xcfacafd2, 0xe46bea80, 0xccc07c79,
        }
    };

    for (const auto& t : tests) {
        uint32_t a = t.ia;
        uint32_t b = t.ib;
        uint32_t c = t.ic;
        uint32_t d = t.id;
        quarter_round(a, b, c, d);
        FUNTLS_ASSERT_EQUAL(t.oa, a);
        FUNTLS_ASSERT_EQUAL(t.ob, b);
        FUNTLS_ASSERT_EQUAL(t.oc, c);
        FUNTLS_ASSERT_EQUAL(t.od, d);
    }
}

void test_block()
{
    const std::vector<uint8_t> key{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const std::vector<uint8_t> nonce{0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
    const uint32_t block_count = 1;
    state s;
    initial_state(s, key.data(), nonce.data(), block_count);
    const state expected_initial{
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    0x00000001, 0x09000000, 0x4a000000, 0x00000000};
    FUNTLS_ASSERT_EQUAL(expected_initial, s);

    const state after_block {
    0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
    0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
    0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
    0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2};
    block(s);
    FUNTLS_ASSERT_EQUAL(after_block, s);
    const std::array<uint8_t, block_length_bytes> serialized{
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e};
    std::array<uint8_t, block_length_bytes> result;
    chacha20_block(result.data(), key.data(), nonce.data(), block_count);
    FUNTLS_ASSERT_EQUAL(serialized, result);
}

void test_chacha20()
{
    const std::vector<uint8_t> key{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const std::vector<uint8_t> nonce{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
    const std::vector<uint8_t> input{
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, // Ladies and Gentl
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, // emen of the clas
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, // s of '99: If I c
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, // ould offer you o
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, // nly one tip for
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, // the future, suns
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, // creen would be i
    0x74, 0x2e                                                                                      // t.
    };
    const std::vector<uint8_t> expected{
    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81, // n.5.%h..A..(..i.
    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, // .~z..C`..'......
    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, // ..e.RG3..Y=..b.W
    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, // .9.$.QR..S.5..a.
    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, // ....P.jaV....".^
    0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, // R.QM.........y76
    0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42, // Z...t.[......x^B
    0x87, 0x4d                                                                                      // .M
    };
    FUNTLS_ASSERT_EQUAL(expected, chacha20(key, nonce, input));
}

void test_poly1305_key_gen()
{
    const std::vector<uint8_t> key{
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
    const std::vector<uint8_t> nonce{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const std::vector<uint8_t> expected_key{
    0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71, // ....._...P@'J..q
    0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46, // .3.7...........F
    };
    FUNTLS_ASSERT_EQUAL(expected_key, poly1305_key_gen(key, nonce));
}

int main()
{
    test_rotate();
    test_quarter_round();
    test_block();
    test_chacha20();
    test_poly1305_key_gen();
}