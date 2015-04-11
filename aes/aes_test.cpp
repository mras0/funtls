#include <iostream>

#include <aes/aes.h>
#include <util/base_conversion.h>
#include <util/test.h>

#include "aes_impl.cpp"

using namespace funtls;

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& v)
{
    return os << funtls::util::base16_encode(v);
}

std::ostream& operator<<(std::ostream& os, const state& s) {
    for (unsigned row = 0; row < 4; ++row) {
        os << '\n';
        for (unsigned col = 0; col < Nb; ++col) {
            if (col) os << ' ';
            const uint8_t b = s(row, col);
            os << util::base16_encode(&b, 1);
        }
    }
    return os;
}

void tests_aes_internals()
{
    //
    // Key expansion
    //
    const auto key_128 = "2b7e151628aed2a6abf7158809cf4f3c";
    const auto expanded_key_128 =
        "2B7E151628AED2A6ABF7158809CF4F3CA0FAFE1788542CB123A339392A6C7605F2"
        "C295F27A96B9435935807A7359F67F3D80477D4716FE3E1E237E446D7A883BEF44"
        "A541A8525B7FB671253BDB0BAD00D4D1C6F87C839D87CAF2B8BC11F915BC6D88A3"
        "7A110B3EFDDBF98641CA0093FD4E54F70E5F5FC9F384A64FB24EA6DC4FEAD27321"
        "B58DBAD2312BF5607F8D292FAC7766F319FADC2128D12941575C006ED014F9A8C9"
        "EE2589E13F0CC8B6630CA6";
    FUNTLS_ASSERT_EQUAL(expanded_key_128, util::base16_encode(KeyExpansion(util::base16_decode(key_128))));

    const auto key_192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    const auto expanded_key_192 =
        "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7BFE0C91F72402F5A5EC"
        "12068E6C827F6B0E7A95B95C56FEC24DB7B4BD69B5411885A74796E92538FDE75F"
        "AD44BB095386485AF05721EFB14FA448F6D94D6DCE24AA326360113B30E6A25E7E"
        "D583B1CF9A27F939436A94F767C0A69407D19DA4E1EC1786EB6FA64971485F7032"
        "22CB8755E26D135233F0B7B340BEEB282F18A2596747D26B458C553EA7E1466C94"
        "11F1DF821F750AAD07D753CA4005388FCC5006282D166ABC3CE7B5E98BA06F448C"
        "773C8ECC720401002202";
    FUNTLS_ASSERT_EQUAL(expanded_key_192, util::base16_encode(KeyExpansion(util::base16_decode(key_192))));

    const auto key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const auto expanded_key_256 =
        "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF49B"
        "A354118E6925AFA51A8B5F2067FCDEA8B09C1A93D194CDBE49846EB75D5B9AD59A"
        "ECB85BF3C917FEE94248DE8EBE96B5A9328A2678A647983122292F6C79B3812C81"
        "ADDADF48BA24360AF2FAB8B46498C5BFC9BEBD198E268C3BA709E0421468007BAC"
        "B2DF331696E939E46C518D80C814E20476A9FB8A5025C02D59C58239DE1369676C"
        "CC5A71FA2563959674EE155886CA5D2E2F31D77E0AF1FA27CF73C3749C47AB1850"
        "1DDAE2757E4F7401905ACAFAAAE3E4D59B349ADF6ACEBD10190DFE4890D1E6188D"
        "0B046DF344706C631E";
    FUNTLS_ASSERT_EQUAL(expanded_key_256, util::base16_encode(KeyExpansion(util::base16_decode(key_256))));

    //
    // Multiply
    //

    FUNTLS_ASSERT_EQUAL(0xb4, multiply(0x5A, 2));
    FUNTLS_ASSERT_EQUAL(0x9d, multiply(0xC3, 2));
    FUNTLS_ASSERT_EQUAL(0xff, multiply(0xF2, 2));

    FUNTLS_ASSERT_EQUAL(0xAE, xtime(0x57));
    FUNTLS_ASSERT_EQUAL(0x47, xtime(0xAE));
    FUNTLS_ASSERT_EQUAL(0x8E, xtime(0x47));
    FUNTLS_ASSERT_EQUAL(0x07, xtime(0x8E));
    FUNTLS_ASSERT_EQUAL(0xFE, multiply(0x57, 0x13));

    FUNTLS_ASSERT_EQUAL(0x63, (unsigned)multiply(0x21, 3));
    FUNTLS_ASSERT_EQUAL(0xff, (unsigned)multiply(0x55, 3));
    FUNTLS_ASSERT_EQUAL(0xfa, (unsigned)multiply(0x56, 3));
    FUNTLS_ASSERT_EQUAL(0xee, (unsigned)multiply(0x5A, 3));
    FUNTLS_ASSERT_EQUAL(0x5e, (unsigned)multiply(0xC3, 3));
    FUNTLS_ASSERT_EQUAL(0x0d, (unsigned)multiply(0xF2, 3));

    FUNTLS_ASSERT_EQUAL(0xfe, multiply(0x57, 0x13));

    //
    // ShiftRows / InvShiftRows
    //

    const auto model_vec = util::base16_decode("00102030011121310212223203132333");
    state q{model_vec};
    ShiftRows(q);
    FUNTLS_ASSERT_EQUAL("00112233011223300213203103102132", util::base16_encode(std::vector<uint8_t>{q.begin(),q.end()}));
    InvShiftRows(q);
    FUNTLS_ASSERT_EQUAL(model_vec, (std::vector<uint8_t>{q.begin(),q.end()}));

    q = state{model_vec};
    InvShiftRows(q);
    FUNTLS_ASSERT_EQUAL(util::base16_decode("00132231011023320211203303122130"), (std::vector<uint8_t>{q.begin(),q.end()}));

    //
    // MixColumns / InvMixColumns
    //
    {
        const auto ss = util::base16_decode("D4BF5D30E0B452AEB84111F11E2798E5");
        const auto ex = "046681E5E0CB199A48F8D37A2806264C";
        auto s = state{ss};
        MixColumns(s);
        FUNTLS_ASSERT_EQUAL(ex, util::base16_encode(std::vector<uint8_t>(s.begin(), s.end())));
        InvMixColumns(s);
        FUNTLS_ASSERT_EQUAL(ss, std::vector<uint8_t>(s.begin(), s.end()));
    }

    //
    // SubBytes / InvSubBytes
    //
    {
        // Make sure all bytes round trip
        for (unsigned i = 0; i < 16; ++i) {
            state s{std::vector<uint8_t>(16)};
            for (unsigned j = 0; j < 16; ++j) {
                s[j] = i*16 + j;
            }
            SubBytes(s);
            InvSubBytes(s);
            for (unsigned j = 0; j < 16; ++j) {
                FUNTLS_ASSERT_EQUAL(unsigned(i*16 + j), unsigned(s[j]));
            }
        }
    }

    // FIPS 197 C.1-3
    {
        const auto input     = util::base16_decode("00112233445566778899aabbccddeeff");
        const auto key       = util::base16_decode("000102030405060708090a0b0c0d0e0f");
        const auto expeceted = util::base16_decode("69c4e0d86a7b0430d8cdb78070b4c55a");
        FUNTLS_ASSERT_EQUAL(expeceted, aes::aes_encrypt_ecb(key, input));
    }
    {
        const auto input     = util::base16_decode("00112233445566778899aabbccddeeff");
        const auto key       = util::base16_decode("000102030405060708090a0b0c0d0e0f1011121314151617");
        const auto expeceted = util::base16_decode("dda97ca4864cdfe06eaf70a0ec0d7191");
        FUNTLS_ASSERT_EQUAL(expeceted, aes::aes_encrypt_ecb(key, input));
    }
    {
        const auto input     = util::base16_decode("00112233445566778899aabbccddeeff");
        const auto key       = util::base16_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const auto expeceted = util::base16_decode("8ea2b7ca516745bfeafc49904b496089");
        FUNTLS_ASSERT_EQUAL(expeceted, aes::aes_encrypt_ecb(key, input));
    }
}

#define AES_ECB_TEST(expected, input)                                    \
    do {                                                                 \
        const auto _in        = util::base16_decode(input);              \
        const auto _encrypted = aes::aes_encrypt_ecb(key, _in);          \
        FUNTLS_ASSERT_EQUAL(util::base16_decode(expected), _encrypted);  \
        FUNTLS_ASSERT_EQUAL(_in, aes::aes_decrypt_ecb(key, _encrypted)); \
    } while (0)

// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
void test_ecb_aes128()
{
    const auto key = util::base16_decode("2b7e151628aed2a6abf7158809cf4f3c");
    // F.1.1 ECB-AES128.Encrypt
    AES_ECB_TEST("3ad77bb40d7a3660a89ecaf32466ef97", "6bc1bee22e409f96e93d7e117393172a");
    AES_ECB_TEST("f5d3d58503b9699de785895a96fdbaaf", "ae2d8a571e03ac9c9eb76fac45af8e51");
    AES_ECB_TEST("43b1cd7f598ece23881b00e3ed030688", "30c81c46a35ce411e5fbc1191a0a52ef");
    AES_ECB_TEST("7b0c785e27e8ad3f8223207104725dd4", "f69f2445df4f9b17ad2b417be66c3710");
    // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf Appendix-B
    AES_ECB_TEST("3925841d02dc09fbdc118597196a0b32", "3243f6a8885a308d313198a2e0370734");
}

void test_ecb_aes192() // F.1.3
{
    const auto key = util::base16_decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    AES_ECB_TEST("bd334f1d6e45f25ff712a214571fa5cc", "6bc1bee22e409f96e93d7e117393172a");
    AES_ECB_TEST("974104846d0ad3ad7734ecb3ecee4eef", "ae2d8a571e03ac9c9eb76fac45af8e51");
    AES_ECB_TEST("ef7afd2270e2e60adce0ba2face6444e", "30c81c46a35ce411e5fbc1191a0a52ef");
    AES_ECB_TEST("9a4b41ba738d6c72fb16691603c18e0e", "f69f2445df4f9b17ad2b417be66c3710");
}

void test_ecb_aes256() // F.1.5
{
    const auto key = util::base16_decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    AES_ECB_TEST("f3eed1bdb5d2a03c064b5a7e3db181f8", "6bc1bee22e409f96e93d7e117393172a");
    AES_ECB_TEST("591ccb10d410ed26dc5ba74a31362870", "ae2d8a571e03ac9c9eb76fac45af8e51");
    AES_ECB_TEST("b6ed21b99ca6f4f9f153e7b1beafed1d", "30c81c46a35ce411e5fbc1191a0a52ef");
    AES_ECB_TEST("23304b7a39f9f3ff067d8d8f9e24ecc7", "f69f2445df4f9b17ad2b417be66c3710");
}

#define AES_CBC_TEST()                                                         \
    do {                                                                       \
        const auto _encrypted = aes::aes_encrypt_cbc(key, iv, input);          \
        FUNTLS_ASSERT_EQUAL(expected, _encrypted);                             \
        FUNTLS_ASSERT_EQUAL(input, aes::aes_decrypt_cbc(key, iv, _encrypted)); \
    } while (0)

//FUNTLS_ASSERT_EQUAL(input, aes::aes_decrypt_ecb(key, _encrypted));


void test_cbc_aes128() // F.2.1
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

void test_cbc_aes192() // F.2.3
{
    const auto key      = util::base16_decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    const auto iv       = util::base16_decode("000102030405060708090a0b0c0d0e0f");
    const auto input    = util::base16_decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    const auto expected = util::base16_decode(
            "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a"
            "571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd");

    AES_CBC_TEST();
}

void test_cbc_aes256() // F.2.5
{
    const auto key      = util::base16_decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    const auto iv       = util::base16_decode("000102030405060708090a0b0c0d0e0f");
    const auto input    = util::base16_decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    const auto expected = util::base16_decode(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");
    AES_CBC_TEST();
}

// http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf

bool bit_set(const state& s, int count)
{
    assert(count >= 0 && count < 128);
    return ((s[count/8] >> (7 - count % 8)) & 1) != 0;
}

state blockmul(const state& x, const state& y)
{
    state z{};
    state v = y;
    for (int i = 0; i < 128; ++i) {
        if (bit_set(x, i)) {
            z ^= v;
        }
        if (bit_set(v, 127)) {
            v >>= 1;
            v[0] ^= 0xE1; // v ^= r; r = 11100001 || 0_120
        } else {
            v >>= 1;
        }
    }
    return z;
}

#if 0
state ghash_h(const std::vector<uint8_t>& H, const std::vector<uint8_t>& X)
{
    assert(H.size() == aes::block_size_bytes);
    assert(X.size() % aes::block_size_bytes == 0);

    state Y; // start with zero block
    for (size_t i = 0; i < X.size(); i += aes::block_size_bytes) {
        // Y_i = (Y_{i-1} ^ X_i) * H
        Y ^= state{&X[i]};
        Y = blockmul(Y, state{H});
    }
    return Y;
}
#endif

void one_block(state& X, const state& H, const state& in)
{
    std::cout << "one_block()\n";
    std::cout << "  X = " << util::base16_encode(X.as_vector()) << std::endl;
    std::cout << "  H = " << util::base16_encode(H.as_vector()) << std::endl;
    std::cout << "  i = " << util::base16_encode(in.as_vector()) << std::endl;
    X ^= in;
    X = blockmul(X, H);
    std::cout << "  o = " << util::base16_encode(X.as_vector()) << std::endl;
}

void process_with_padding(state& X, const state& H, const std::vector<uint8_t>& in)
{
    size_t i = 0;
    for (; i + aes::block_size_bytes - 1 < in.size(); i += aes::block_size_bytes) {
        one_block(X, H, state{&in[i]});
    }
    const size_t remaining = in.size() - i;
    if (remaining) {
        assert(remaining < aes::block_size_bytes);
        state last;
        memcpy(&last[0], &in[i], remaining);
        one_block(X, H, last);
    }
}

state ghash(const std::vector<uint8_t>& H, const std::vector<uint8_t>& A, const std::vector<uint8_t>& C)
{
    // GHASH(H, A, C) = X_{m+n+1} where A has size m, C size n
    std::cout << "GHASH\n";
    std::cout << "H  " << util::base16_encode(H) << std::endl;
    std::cout << "A  " << util::base16_encode(A) << std::endl;
    std::cout << "C  " << util::base16_encode(C) << std::endl;
    state X{};

    process_with_padding(X, H, A);
    process_with_padding(X, H, C);
    std::vector<uint8_t> l(aes::block_size_bytes);
    for (int i = 7; i >= 0; i--) {
        l[7-i] = static_cast<uint8_t>((A.size()*8)>>(8*i));
        l[15-i] = static_cast<uint8_t>((C.size()*8)>>(8*i));
    }
    std::cout << "L  " << util::base16_encode(l) << std::endl;
    process_with_padding(X, H, l); // len(A)||len(C)

    std::cout << "X  " << util::base16_encode(X.as_vector()) << std::endl;
    return X;
}

void incr32(state& s)
{
    ++s[15];
    if (!s[15]) {
        ++s[14];
        if (!s[14]) {
            ++s[13];
            if (!s[13]) {
                ++s[12];
            }
        }
    }
}

// K:  secret key, whose length is appropriate for the underlying block cipher
// IV: initialization vector
// P:  plaintext
// A:  additional data
//
// returns C (cipher text), T (authentication tag)
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> aes_cgm(const std::vector<uint8_t>& K, const std::vector<uint8_t>& IV, const std::vector<uint8_t>& P, const std::vector<uint8_t>& A)
{
    using namespace funtls::aes;

    std::cout << "Input\n";
    std::cout << "K  " << util::base16_encode(K) << std::endl;
    std::cout << "IV " << util::base16_encode(IV) << std::endl;
    std::cout << "P  " << util::base16_encode(P) << std::endl;
    std::cout << "A  " << util::base16_encode(A) << std::endl;
    std::cout << "\n";

    auto E_K = [&](const std::vector<uint8_t>& input) { return aes_encrypt_ecb(K, input); };

    const auto H = E_K(std::vector<uint8_t>(block_size_bytes)); // H=E(K, 0_128);
    state Y;
    if (IV.size() == 96/8) {
        // Y_0 = IV || 0_31 || 1_1
        std::copy(IV.begin(), IV.end(), Y.begin());
        assert(Y[12] == 0);
        assert(Y[13] == 0);
        assert(Y[14] == 0);
        assert(Y[15] == 0);
        Y[15] |= 1;
    } else {
        Y = ghash(H, std::vector<uint8_t>{}, IV);
    }
    const auto Y0 = Y.as_vector();

    std::cout << "H =  " << util::base16_encode(H) << std::endl;
    std::cout << "Y0 = " << util::base16_encode(Y0) << std::endl;

    std::vector<uint8_t> C(P.size());
    for (unsigned i = 0; i < P.size(); i += aes::block_size_bytes) {
        unsigned remaining = P.size() - i;
        state c;
        if (remaining >= aes::block_size_bytes) {
            remaining = aes::block_size_bytes;
            c = state{&P[i]};
        } else {
            memcpy(&c[0], &P[i], remaining);
        }
        incr32(Y);
        std::cout << "Iter " << (1+i/aes::block_size_bytes) << std::endl;
        std::cout << "P  = " << util::base16_encode(c.as_vector()) << std::endl;
        std::cout << "Y  = " << util::base16_encode(Y.as_vector()) << std::endl;
        const auto E_K_Y = state{E_K(Y.as_vector())};
        std::cout << "EY = " << util::base16_encode(E_K_Y.as_vector()) << std::endl;
        c ^= E_K_Y;
        std::cout << "C  = " << util::base16_encode(c.as_vector()) << std::endl;
        std::copy(c.begin(), c.begin() + remaining, &C[i]);
    }

    // T = MSB_t(GHASH(H, A, C) ^ E(K, Y0))
    auto T_s = ghash(H, A, C);
    T_s ^= E_K(Y0);
    return std::make_pair(std::move(C), std::vector<uint8_t>(T_s.begin(), T_s.end()));
}

// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
void test_cgm_aes()
{
    static const struct {
        const std::string k;
        const std::string p;
        const std::string a;
        const std::string iv;
        const std::string c;
        const std::string t;
    } tests[] = {
        // Test case 1
        {
            "00000000000000000000000000000000",
            "",
            "",
            "000000000000000000000000",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a"
        },
        // Test case 2
        {
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        },
        // Test case 3
        {
            // K
            "feffe9928665731c6d6a8f9467308308",
            // P
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255",
            // A
            "",
            // IV
            "cafebabefacedbaddecaf888",
            // C
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091473f5985",
            // T
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        },
        // Test case 4
        {
            // K
            "feffe9928665731c6d6a8f9467308308",
            // P
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39",
            // A
            "feedfacedeadbeeffeedfacedeadbeef"
            "abaddad2",
            // IV
            "cafebabefacedbaddecaf888",
            // C
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091",
            // T
            "5bc94fbc3221a5db94fae95ae7121a47",
        }
    };

    for (const auto& t : tests) {
        const auto K  = util::base16_decode(t.k);
        const auto IV = util::base16_decode(t.iv);
        const auto P  = util::base16_decode(t.p);
        const auto A  = util::base16_decode(t.a);

        const auto res = aes_cgm(K, IV, P, A);
        const auto& C = res.first;
        const auto& T = res.second;
        FUNTLS_ASSERT_EQUAL(P.size(), C.size());
        FUNTLS_ASSERT_EQUAL(util::base16_decode(t.c), C);
        FUNTLS_ASSERT_EQUAL(util::base16_decode(t.t), T);
    }
}

int main()
{
    tests_aes_internals();
    test_ecb_aes128();
    test_ecb_aes192();
    test_ecb_aes256();
    test_cbc_aes128();
    test_cbc_aes192();
    test_cbc_aes256();

    test_cgm_aes();
}
