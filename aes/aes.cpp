#include "aes.h"

#include <cassert>
#include <string>

#include <util/test.h>
#include <util/base_conversion.h>

#include "aes_impl.cpp"

//#define FUNTLS_AES_VERBOSE

#ifdef FUNTLS_AES_VERBOSE
#include <iostream>
#include <util/base_conversion.h>
#endif

using namespace funtls;

namespace {

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& v)
{
    return os << util::base16_encode(v);
}

} // unnamed namespace

namespace funtls { namespace aes {

//For the AES algorithm, the length of the Cipher Key, K, is 128, 192, or 256 bits. The key
//length is represented by Nk = 4, 6, or 8, which reflects the number of 32-bit words (number of
//columns) in the Cipher Key.
//For the AES algorithm, the number of rounds to be performed during the execution of the
//algorithm is dependent on the key size. The number of rounds is represented by Nr, where Nr =
//10 when Nk = 4, Nr = 12 when Nk = 6, and Nr = 14 when Nk = 8. 

std::vector<uint8_t> aes_encrypt_ecb(const std::vector<uint8_t>& K, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(K.size() % 4, ==, 0, "Unexpected key size " + std::to_string(K.size()));
    const unsigned Nk = Nk_from_size(static_cast<unsigned>(K.size()));
    FUNTLS_CHECK_BINARY(valid_Nk(Nk), ==, true, "Unexpected key size " + std::to_string(K.size()));
    FUNTLS_CHECK_BINARY(input.size(), ==, 16, "Input must be 128-bit");
    const unsigned Nr = Nr_from_Nk(Nk);

    // Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
    // in = input
    // w = KeyExpansion(K)
    // returns out
    const auto w = KeyExpansion(K);
    FUNTLS_ASSERT_EQUAL(Nb*(Nr+1)*4, w.size());

    // After an initial Round Key addition, the State array is transformed by implementing a
    // round function 10, 12, or 14 times (depending on the key length), with the final round differing
    // slightly from the first Nr-1 rounds.

    state s{input}; // state = in

    AddRoundKey(s, &w[0*Nb*4]); // AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4

    for (unsigned round = 1; round < Nr; ++round) { // for round = 1 step 1 to Nr–1
        SubBytes(s); // SubBytes(state) // See Sec. 5.1.1
        ShiftRows(s); // ShiftRows(state) // See Sec. 5.1.2
        MixColumns(s); // MixColumns(state) // See Sec. 5.1.3
        AddRoundKey(s, &w[round*Nb*4]);// AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
    } // end for

    SubBytes(s); // SubBytes(state)
    ShiftRows(s); // ShiftRows(state)
    AddRoundKey(s, &w[Nr*Nb*4]); // AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])

    return std::vector<uint8_t>{s.begin(),s.end()}; // out = state
}


std::vector<uint8_t> aes_encrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(input.size() % 16, ==, 0, "Input must be a multiple of 128-bit. Size="+std::to_string(input.size()));

    std::vector<uint8_t> last_c = iv;

#ifdef FUNTLS_AES_VERBOSE
    std::cout << "Key          " << util::base16_encode(key) << std::endl;
    std::cout << "IV           " << util::base16_encode(iv) << std::endl;
#endif

    std::vector<uint8_t> output;
    for (size_t i = 0; i < input.size(); i += 16) {
#ifdef FUNTLS_AES_VERBOSE
        std::cout << "Block #" << (1+i/16) << std::endl;
        std::cout << "Plaintext    " << util::base16_encode(&input[i], 16) << std::endl;
#endif
        std::vector<uint8_t> this_block(16);
        for (size_t j = 0; j < 16; ++j) {
            this_block[j] = input[i + j] ^ last_c[j];
        }
#ifdef FUNTLS_AES_VERBOSE
        std::cout << "Input Block  " << util::base16_encode(&this_block[0], 16) << std::endl;
#endif
        auto res = aes_encrypt_ecb(key, this_block);
        assert(res.size() == 16);
        output.insert(output.end(), res.begin(), res.end());
#ifdef FUNTLS_AES_VERBOSE
        std::cout << "Output Block " << util::base16_encode(&res[0], 16) << std::endl;
#endif
        last_c = res;
    }

    return output;
}

std::vector<uint8_t> aes_decrypt_ecb(const std::vector<uint8_t>& K, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(K.size() % 4, ==, 0, "Unexpected key size " + std::to_string(K.size()));
    const unsigned Nk = Nk_from_size(static_cast<unsigned>(K.size()));
    FUNTLS_CHECK_BINARY(valid_Nk(Nk), ==, true, "Unexpected key size " + std::to_string(K.size()));
    FUNTLS_CHECK_BINARY(input.size(), ==, 16, "Input must be 128-bit");
    const unsigned Nr = Nr_from_Nk(Nk);

    state s{input}; // state = in

    const auto w = KeyExpansion(K);
    FUNTLS_ASSERT_EQUAL(Nb*(Nr+1)*4, w.size());

    AddRoundKey(s, &w[Nr*Nb*4]); // AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])

    for (unsigned round = Nr-1; round >= 1; --round) {
        InvShiftRows(s);
        InvSubBytes(s);
        AddRoundKey(s, &w[round*Nb*4]);// AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
        InvMixColumns(s);
    }

    InvShiftRows(s);
    InvSubBytes(s);
    AddRoundKey(s, &w[0*Nb*4]); // AddRoundKey(state, w[0, Nb-1])

    return std::vector<uint8_t>{s.begin(),s.end()}; // out = state
}

std::vector<uint8_t> aes_decrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(input.size() % 16, ==, 0, "Input must be a multiple of 128-bit. Size="+std::to_string(input.size()));

    std::vector<uint8_t> last_c = iv;

#ifdef FUNTLS_AES_VERBOSE
    std::cout << "Key          " << util::base16_encode(key) << std::endl;
    std::cout << "IV           " << util::base16_encode(iv) << std::endl;
#endif

    std::vector<uint8_t> output;
    for (size_t i = 0; i < input.size(); i += 16) {
#ifdef FUNTLS_AES_VERBOSE
        std::cout << "Block #" << (1+i/16) << std::endl;
#endif
        std::vector<uint8_t> this_block(16);
        for (size_t j = 0; j < 16; ++j) {
            this_block[j] = input[i + j];
        }
#ifdef FUNTLS_AES_VERBOSE
        std::cout << "Input Block  " << util::base16_encode(&this_block[0], 16) << std::endl;
#endif
        auto res = aes_decrypt_ecb(key, this_block);
        assert(res.size() == 16);
#ifdef FUNTLS_AES_VERBOSE
        std::cout << "Output Block " << util::base16_encode(&res[0], 16) << std::endl;
#endif
        for (size_t j = 0; j < 16; ++j) {
            res[j] ^= last_c[j];
        }
#ifdef FUNTLS_AES_VERBOSE
        std::cout << "Plaintext    " << util::base16_encode(&res[0], 16) << std::endl;
#endif

        output.insert(output.end(), res.begin(), res.end());
        last_c = this_block;
    }

    return output;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> aes_encrypt_gcm(const std::vector<uint8_t>& K, const std::vector<uint8_t>& IV, const std::vector<uint8_t>& P, const std::vector<uint8_t>& A)
{
    using namespace funtls::aes;

    auto E_K = [&](const std::vector<uint8_t>& input) { return aes_encrypt_ecb(K, input); };

    const auto H = E_K(std::vector<uint8_t>(block_size_bytes)); // H=E(K, 0_128);
    state Y = initial_y(H, IV);
    const auto Y0 = Y.as_vector();

    auto C = aes_gcm_inner(E_K, Y, P);

    // T = MSB_t(GHASH(H, A, C) ^ E(K, Y0))
    auto T_s = ghash(H, A, C);
    T_s ^= E_K(Y0);
    return std::make_pair(std::move(C), std::vector<uint8_t>(T_s.begin(), T_s.end()));
}

std::vector<uint8_t> aes_decrypt_gcm(const std::vector<uint8_t>& K, const std::vector<uint8_t>& IV, const std::vector<uint8_t>& C, const std::vector<uint8_t>& A, const std::vector<uint8_t>& T)
{
    using namespace funtls::aes;

    auto E_K = [&](const std::vector<uint8_t>& input) { return aes_encrypt_ecb(K, input); };

    const auto H = E_K(std::vector<uint8_t>(block_size_bytes)); // H=E(K, 0_128);
    state Y = initial_y(H, IV);
    const auto Y0 = Y.as_vector();

    // T' = MSB_t(GHASH(H, A, C) ^ E(K, Y0))
    auto T_calced = ghash(H, A, C);
    T_calced ^= E_K(Y0);

    FUNTLS_CHECK_BINARY(T, ==, T_calced.as_vector(), "Signature check failed");

    return aes_gcm_inner(E_K, Y, C);
}

void increment_be_number(uint8_t* n, size_t len)
{
    assert(len);
    size_t i = len-1;
    do {
        ++n[i];
        if (n[i]) break;
    } while(i--);
}

} } // namespace funtls::aes
