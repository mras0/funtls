

// TEMP!!!
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



// 3DES numbers bytes _and bits_ big endian style
uint64_t _3des_get_u64(const uint8_t* src)
{
    uint64_t res = 0;
    for (unsigned i = 0; i < sizeof(res); ++i) {
        res = (res<<8) | src[i];
    }
    return res;
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

uint32_t feistel(uint32_t r, uint64_t key)
{
    assert((key >> 48) == 0); // Only 48 bits of the key are used
    // Stage 1. Expansion — the 32-bit half-block is expanded to 48 bits using the expansion permutation,
    //          by duplicating half of the bits. The output consists of eight 6-bit (8 * 6 = 48 bits) pieces,
    //          each containing a copy of 4 corresponding input bits, plus a copy of the immediately adjacent
    //          bit from each of the input pieces to either side.
    std::cout << "r = " << bin(r, 4) << std::endl;
    const auto e = permute_bits(r, 32, e_bit_selection_table);
    std::cout << "e = " << bin(e, 6, 48) << std::endl;
    assert((e>>48)==0);
    // Stage 2. Key mixing — the result is combined with a subkey using an XOR operation.
    //          16 48-bit subkeys — one for each round — are derived from the main key using the key schedule
    const auto m = e ^ key;
    std::cout << "m = " << bin(m, 6, 48) << std::endl;
    assert((m>>48)==0);
    // Stage 3. Substitution — after mixing in the subkey, the block is divided into eight 6-bit pieces 
    //          before processing by the S-boxes, or substitution boxes.
    //          Each of the eight S-boxes replaces its six input bits with four output bits 
    //          according to a non-linear transformation, provided in the form of a lookup table.
    //          The S-boxes provide the core of the security of DES — without them, the cipher would be linear,
    //          and trivially breakable.
    const auto s = m;
    std::cout << "s = " << bin(s, 4) << std::endl;
    // Stage 4. Permutation — finally, the 32 outputs from the S-boxes are rearranged according to a fixed 
    //          permutation, the P-box. This is designed so that, after permutation, each S-box's output bits
    //          are spread across 4 different S boxes in the next round.
    const auto p = permute_bits(s, 32, p_box);
    std::cout << "p = " << bin(p, 4) << std::endl;
    assert(!"Not implemented");
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
    std::cout << "K  " << bin(key, 8) << "\n";
    std::cout << "K+ " << bin((static_cast<uint64_t>(c)<<28)|d, 7, 56) << "\n";
    for (unsigned round = 0; round < num_des_rounds; ++round) {
        std::cout << "Round " << round+1 << "\n";

        for (uint8_t s = 0; s < num_left_shifts[round]; ++s) {
            c = rotate_left_28(c);
            d = rotate_left_28(d);
        }

        std::cout << "c  " << bin(c, 28, 28) << "\n";
        std::cout << "d  " << bin(d, 28, 28) << "\n";
        ks[round] = permute_bits((static_cast<uint64_t>(c)<<28)|d, 56, permuted_choice_2);
        assert((ks[round] >> 48) == 0); // Only 48 bits of the key are used
        std::cout << "Kn " << bin(ks[round], 6, 48) << "\n";
    }
}

uint64_t des(uint64_t key, uint64_t input)
{
    std::cout << "K " << bin(key, 8) << "\nM " << bin(input, 4) << std::endl;

    // Produce key schedule from key
    uint64_t Kn[num_des_rounds];
    key_schedule(Kn, key);

    // Initial permutation
    input = initial_permute(input);
    std::cout << "After intial permute:\n" << bin(input, 4) << std::endl;
    // Divide into 2 32-bit halves
    uint32_t l = input>>32;
    uint32_t r = input;

    // Do 16 rounds of "F" (apply the Feistel function)
    for (unsigned round = 0; round < num_des_rounds; ++round) {
        std::cout << "Round " << round+1 << "\nL  " << bin(l, 4) << "\nR  " << bin(r, 4) << "\nKn " << bin(Kn[round], 6, 48) << std::endl;
        const uint32_t next_l = r;
        r = l ^ feistel(r, Kn[round]);
        l = next_l;
    }

    std::cout << "Preout block: " << bin(r, 4) << " " << bin(l, 4) << std::endl;
    // Final permutation (inverse of the initial permutation)
    // Note: that r and l are reversed in the preoutput block
    return inverse_initial_permute((static_cast<uint64_t>(r)<<32)|l);
}

uint64_t _3des_encrypt(uint64_t key, uint64_t input)
{
    // ciphertext = EK3(DK2(EK1(plaintext)))
    (void)key;(void)input;
    return 0;
}

uint64_t _3des_decrypt(uint64_t key, uint64_t input)
{
    // plaintext = DK1(EK2(DK3(ciphertext)))
    (void)key;(void)input;
    return 0;
}

