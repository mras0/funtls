#include <3des/3des.h>
#include <util/test.h>
#include <cassert>

#include <iostream>

using namespace funtls;

namespace {
#if 0
template<typename T>
std::string bin(T x, int group, int n=sizeof(T)*8)
{
    assert(n==sizeof(T)*8||(x>>n)==0);
    std::string s;
    for (int i=n-1; i>=0; i--) {
        if (i!=n-1&&(i+1)%group==0) s+=' ';
        s+='0'+((x>>i)&1);
    }
    return s;
}
#endif

// 3DES numbers bytes _and bits_ big endian style
uint64_t _3des_get_u64(const uint8_t* src)
{
    uint64_t res = 0;
    for (unsigned i = 0; i < sizeof(res); ++i) {
        res = (res<<8) | src[i];
    }
    return res;
}

void _3des_put_u64(uint8_t* dst, uint64_t n)
{
    for (unsigned i = 0; i < sizeof(n); ++i) {
        dst[i] = static_cast<uint8_t>(n >> (8*(sizeof(n)-1-i)));
    }
}

template<size_t NumBits>
uint64_t permute_bits(uint64_t i, unsigned isize, const uint8_t (&table)[NumBits])
{
    assert(isize==64 || (i>>isize)==0);
    static_assert(NumBits <= 64, "Too many bits");
    uint64_t o = 0;

    for (unsigned n = 0; n < NumBits; ++n) {
        assert(table[n] >= 1 && table[n] <= isize);
        const unsigned bitn = isize-table[n];
        o |= static_cast<uint64_t>((i >> bitn) & 1) << (NumBits-1-n);
    }
    return o;
}

uint64_t initial_permute(uint64_t i)
{
    static const uint8_t IP[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    return permute_bits(i, 64, IP);
}

uint64_t inverse_initial_permute(uint64_t i)
{
    static const uint8_t inv_IP[64] = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    };
    return permute_bits(i, 64, inv_IP);
}

static const uint8_t e_bit_selection_table[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

static const uint8_t p_box[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
};

uint8_t sub(uint8_t b, unsigned group)
{
    assert(b < 64);
    assert(group >= 1 && group <= 8);

    const uint8_t i = ((b >> 5)<<1) | (b&1); // The first and last bits of B represent in base 2 a number in the decimal range 0 to 3
    const uint8_t j = (b >> 1) & 15; // The middle 4 bits of B represent in base 2 a number in the decimal range 0 to 15

    //std::cout << "sub(b=" << bin(b, 6, 6) << ", group=" << group << ")" << std::endl;
    //std::cout << "i = " << std::dec << int(i) << " j = " << int(j) << std::endl;

    static const uint8_t S[8*16*4] {
                             // S1

     14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7,
      0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8,
      4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0,
     15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13,

                             // S2

     15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10,
      3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5,
      0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15,
     13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9,

                             // S3

     10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8,
     13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1,
     13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7,
      1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12,

                             // S4

      7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15,
     13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9,
     10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4,
      3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14,

                             // S5

      2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9,
     14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6,
      4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14,
     11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3,

                             // S6

     12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11,
     10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8,
      9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6,
      4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13,

                             // S7

      4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1,
     13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6,
      1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2,
      6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12,

                             // S8

     13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7,
      1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2,
      7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8,
      2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11,

    };

    //std::cout << "res " <<  int(S[(group-1)*64+i*16+j]) << std::endl;
    return S[(group-1)*64+i*16+j];
}

uint32_t feistel(uint32_t r, uint64_t key)
{
    assert((key >> 48) == 0); // Only 48 bits of the key are used
    // Stage 1. Expansion — the 32-bit half-block is expanded to 48 bits using the expansion permutation,
    //          by duplicating half of the bits. The output consists of eight 6-bit (8 * 6 = 48 bits) pieces,
    //          each containing a copy of 4 corresponding input bits, plus a copy of the immediately adjacent
    //          bit from each of the input pieces to either side.
    //std::cout << "r = " << bin(r, 4) << std::endl;
    const auto e = permute_bits(r, 32, e_bit_selection_table);
    //std::cout << "e = " << bin(e, 6, 48) << std::endl;
    assert((e>>48)==0);
    // Stage 2. Key mixing — the result is combined with a subkey using an XOR operation.
    //          16 48-bit subkeys — one for each round — are derived from the main key using the key schedule
    const auto m = e ^ key;
    //std::cout << "m = " << bin(m, 6, 48) << std::endl;
    assert((m>>48)==0);
    // Stage 3. Substitution — after mixing in the subkey, the block is divided into eight 6-bit pieces 
    //          before processing by the S-boxes, or substitution boxes.
    //          Each of the eight S-boxes replaces its six input bits with four output bits 
    //          according to a non-linear transformation, provided in the form of a lookup table.
    //          The S-boxes provide the core of the security of DES — without them, the cipher would be linear,
    //          and trivially breakable.
    uint32_t s = 0;
    for (unsigned group = 1; group <= 8; ++group) {
        const uint8_t b = (m >> (48-group*6)) & ((1<<6)-1);
        uint8_t res = sub(b, group);
        assert(res < 16);
        s |= res << (32-group*4);
    }
    //std::cout << "s = " << bin(s, 4) << std::endl;
    // Stage 4. Permutation — finally, the 32 outputs from the S-boxes are rearranged according to a fixed 
    //          permutation, the P-box. This is designed so that, after permutation, each S-box's output bits
    //          are spread across 4 different S boxes in the next round.
    const uint32_t p = permute_bits(s, 32, p_box);
    //std::cout << "p = " << bin(p, 4) << std::endl;
    return p;
}

constexpr unsigned num_des_rounds = 16;

uint32_t rotate_left_28(uint32_t x)
{
    assert((x>>28)==0);
    const uint32_t mask = 1U << 27;
    if (x & mask) {
        return ((x&~mask)<<1)|1;
    } else {
        return (x<<1);
    }
}

void key_schedule(uint64_t (&ks)[num_des_rounds], uint64_t key)
{
    // TODO: Check parity bits of key
    static const uint8_t permuted_choice_1_c_bits[28] = {
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36
    };
    static const uint8_t permuted_choice_1_d_bits[28] = {
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    };
    static const uint8_t permuted_choice_2[48] = {
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21,  10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };
    static const uint8_t num_left_shifts[num_des_rounds] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };
    uint32_t c = permute_bits(key, 64, permuted_choice_1_c_bits);
    uint32_t d = permute_bits(key, 64, permuted_choice_1_d_bits);
    //std::cout << "K  " << bin(key, 8) << "\n";
    //std::cout << "K+ " << bin((static_cast<uint64_t>(c)<<28)|d, 7, 56) << "\n";
    for (unsigned round = 0; round < num_des_rounds; ++round) {
        //std::cout << "Round " << round+1 << "\n";

        for (uint8_t s = 0; s < num_left_shifts[round]; ++s) {
            c = rotate_left_28(c);
            d = rotate_left_28(d);
        }

        //std::cout << "c  " << bin(c, 28, 28) << "\n";
        //std::cout << "d  " << bin(d, 28, 28) << "\n";
        ks[round] = permute_bits((static_cast<uint64_t>(c)<<28)|d, 56, permuted_choice_2);
        assert((ks[round] >> 48) == 0); // Only 48 bits of the key are used
        //std::cout << "Kn " << bin(ks[round], 6, 48) << "\n";
    }
}

enum class des_op { enc, dec };
uint64_t des(des_op op, uint64_t key, uint64_t input)
{
    //std::cout << "K " << bin(key, 8) << "\nM " << bin(input, 4) << std::endl;

    // Produce key schedule from key
    uint64_t Ks[num_des_rounds];
    key_schedule(Ks, key);

    // Initial permutation
    input = initial_permute(input);
    //std::cout << "After intial permute:\n" << bin(input, 4) << std::endl;
    // Divide into 2 32-bit halves
    uint32_t l = input>>32;
    uint32_t r = input;

    // Do 16 rounds of "F" (apply the Feistel function)
    for (unsigned round = 0; round < num_des_rounds; ++round) {
        const auto Kn = Ks[op == des_op::enc ? round : num_des_rounds-1-round];
        //std::cout << "Round " << round << "\nL  " << bin(l, 4) << "\nR  " << bin(r, 4) << "\nKn " << bin(Kn, 6, 48) << std::endl;
        const uint32_t next_l = r;
        r = l ^ feistel(r, Kn);
        l = next_l;
    }
    //std::cout << "Round " << num_des_rounds << "\nL  " << bin(l, 4) << "\nR  " << bin(r, 4) << std::endl;

    //std::cout << "Preout block: " << bin(r, 8) << " " << bin(l, 8) << std::endl;
    // Final permutation (inverse of the initial permutation)
    // Note: that r and l are reversed in the preoutput block
    const auto inved =  inverse_initial_permute((static_cast<uint64_t>(r)<<32)|l);
    //std::cout << "final result: " << bin(inved, 8) << "\n";
    return inved;
}

uint64_t _3des_encrypt_cbc(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t input, uint64_t iv)
{
    return _3des::_3des_encrypt(k1, k2, k3, input ^ iv);
}

uint64_t _3des_decrypt_cbc(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t input, uint64_t iv)
{
    return _3des::_3des_decrypt(k1, k2, k3, input) ^ iv;
}

}

namespace funtls { namespace _3des {

uint64_t _3des_encrypt(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t input)
{
    // ciphertext = EK3(DK2(EK1(plaintext)))
    return des(des_op::enc, k3, des(des_op::dec, k2, des(des_op::enc, k1, input)));
}

uint64_t _3des_decrypt(uint64_t k1, uint64_t k2, uint64_t k3, uint64_t input)
{
    // plaintext = DK1(EK2(DK3(ciphertext)))
    return des(des_op::dec, k1, des(des_op::enc, k2, des(des_op::dec, k3, input)));
}

// TODO: The CBC modes could reuse the key schedule

// Each DES key is nominally stored or transmitted as 8 bytes, each of odd parity
std::vector<uint8_t> _3des_encrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_bytes, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(key.size(), ==, key_length_bytes, "Invalid 3DES key length");
    FUNTLS_CHECK_BINARY(iv_bytes.size(), ==, block_length_bytes, "Invalid 3DES initialization vector length");
    FUNTLS_CHECK_BINARY(input.size() % block_length_bytes, ==, 0,  "Invalid 3DES input length " + std::to_string(input.size()));

    const uint64_t k1 = _3des_get_u64(&key[0*8]);
    const uint64_t k2 = _3des_get_u64(&key[1*8]);
    const uint64_t k3 = _3des_get_u64(&key[2*8]);
    uint64_t iv = _3des_get_u64(&iv_bytes[0]);

    std::vector<uint8_t> output(input.size());
    for (size_t i = 0; i < input.size(); i += block_length_bytes) {
        const uint64_t m = _3des_get_u64(&input[i]);
        const uint64_t c = ::_3des_encrypt_cbc(k1, k2, k3, m, iv);
        _3des_put_u64(&output[i], c);
        iv = c;
    }
    return output;
}

std::vector<uint8_t> _3des_decrypt_cbc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_bytes, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(key.size(), ==, key_length_bytes, "Invalid 3DES key length");
    FUNTLS_CHECK_BINARY(iv_bytes.size(),  ==, block_length_bytes, "Invalid 3DES initialization vector length");
    FUNTLS_CHECK_BINARY(input.size() % block_length_bytes, ==, 0,  "Invalid 3DES input length " + std::to_string(input.size()));

    const uint64_t k1 = _3des_get_u64(&key[0*8]);
    const uint64_t k2 = _3des_get_u64(&key[1*8]);
    const uint64_t k3 = _3des_get_u64(&key[2*8]);
    uint64_t iv = _3des_get_u64(&iv_bytes[0]);

    std::vector<uint8_t> output(input.size());
    for (size_t i = 0; i < input.size(); i += block_length_bytes) {
        const uint64_t c = _3des_get_u64(&input[i]);
        const uint64_t m = ::_3des_decrypt_cbc(k1, k2, k3, c, iv);
        _3des_put_u64(&output[i], m);
        iv = c;
    }
    return output;
}

} } // namespace funtls::_3des
