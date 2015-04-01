#include <cassert>
#include <cstring>

//
// Input bytes to input bit sequence:
//
// +--------------------+---+---+---+---+---+---+---+---+---+---+-....-+-----+-...
// | Input bit sequence | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | .... | 127 | ...
// +--------------------+---+---+---+---+---+---+---+---+---+---+-....-+-----+-...
// | Byte number        |               0               |                15  |
// +--------------------+---+---+---+---+---+---+---+---+---+---+-....-+-----+-...
// | Bit number in byte | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 | 7 | 6 | .... |  0  | ...
// +--------------------+---+---+---+---+---+---+---+---+---+---+-....-+-----+-...
//

namespace {

// Nb Number of columns (32-bit words) comprising the State. For this
// standard, Nb = 4. (Also see Sec. 6.3.)
static constexpr unsigned Nb = 4;

// Nk Number of 32-bit words comprising the Cipher Key. For this
// standard, Nk = 4, 6, or 8. (Also see Sec. 6.3.)

constexpr bool valid_Nk(unsigned Nk) {
    return Nk == 4 || Nk == 6 || Nk == 8;
}

unsigned Nk_from_size(unsigned size) {
    assert(size%4==0);
    assert(valid_Nk(size/4));
    return size / 4;
}

// Nr Number of rounds, which is a function of Nk and Nb (which is
// fixed). For this standard, Nr = 10, 12, or 14. (Also see Sec. 6.3.)
constexpr unsigned Nr_from_Nk(unsigned Nk) {
    return Nk == 4 ? 10 : Nk == 6 ? 12 : 14;
}

// In the polynomial representation, multiplication in GF(2^8) [...] corresponds with the
// multiplication of polynomials modulo an irreducible polynomial of degree 8. A polynomial is
// irreducible if its only divisors are one and itself. For the AES algorithm, this irreducible
// polynomial is m(x) = x^8 + x^4 + x^3 + x + 1 or [0x11b] in hexadecimal notation


uint8_t xtime(uint8_t a)
{
    static constexpr uint16_t mx = 0x11b;
    return a & 0x80 ? (a<<1) ^ mx : (a<<1);
}

uint8_t multiply(uint8_t a, uint8_t b) {
    uint8_t x = 0;
    while (b) {
        if (b & 1) x ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return x;
}

//
// Bytes to state:
//
//   w0   w1   w2   w3            w0    w1    w2    w3
// +----+----+----+----+       +-----+-----+-----+-----+
// |  0 |  4 |  8 | 12 |       | 0,0 | 0,1 | 0,2 | 0,3 |
// +----+----+----+----+       +-----+-----+-----+-----+
// |  1 |  5 |  9 | 13 |       | 1,0 | 1,1 | 0,2 | 1,3 |
// +----+----+----+----+ <===> +-----+-----+-----+-----+
// |  2 |  6 | 10 | 14 |       | 2,0 | 1,1 | 0,2 | 2,3 |
// +----+----+----+----+       +-----+-----+-----+-----+
// |  3 |  7 | 11 | 15 |       | 3,0 | 3,1 | 3,2 | 3,3 |
// +----+----+----+----+       +-----+-----+-----+-----+
//


class state {
public:
    state() {}
    state(const std::vector<uint8_t>& v) {
        assert(v.size() == sizeof(data_));
        memcpy(data_, &v[0], sizeof(data_));
    }

    uint8_t& operator[](unsigned index) {
        assert(index < sizeof(data_));
        return data_[index];
    }

    const uint8_t& operator[](unsigned index) const {
        assert(index < sizeof(data_));
        return data_[index];
    }

    uint8_t& operator()(unsigned row, unsigned col) {
        assert(row < 4);
        assert(col < Nb);
        return (*this)[row + col*4];
    }

    const uint8_t& operator()(unsigned row, unsigned col) const {
        assert(row < 4);
        assert(col < Nb);
        return (*this)[row + col*4];
    }

    uint8_t* begin() { return data_; }
    const uint8_t* begin() const { return data_; }
    uint8_t* end() { return data_ + sizeof(data_); }
    const uint8_t* end() const { return data_ + sizeof(data_); }

private:
    uint8_t data_[4*Nb];
};

// Transformation in the Cipher and Inverse Cipher in which a Round
// Key is added to the State using an XOR operation. The length of a
// Round Key equals the size of the State (i.e., for Nb = 4, the Round
// Key length equals 128 bits/16 bytes)
void AddRoundKey(state& s, const uint8_t* round_key) {
    for (size_t i = 0; i < 4*Nb; ++i) {
        s[i] ^= round_key[i];
    }
}

// Transformation in the Inverse Cipher that is the inverse of MixColumns()
void InvMixColumns() {
    assert(!"Not implemented");
}

// Transformation in the Inverse Cipher that is the inverse of ShiftRows()
void InvShiftRows() {
    assert(!"Not implemented");
}

// Transformation in the Inverse Cipher that is the inverse of SubBytes()
void InvSubBytes() {
    assert(!"Not implemented");
}

// Transformation in the Cipher that takes all of the columns of the
// State and mixes their data (independently of one another) to
// produce new columns
void MixColumns(state& s) {
    const auto i = s; // Copy input
    for (unsigned c = 0; c < Nb; ++c) {
        s(0,c) = multiply(i(0,c),2) ^ multiply(i(1,c),3) ^ i(2,c) ^ i(3,c);
        s(1,c) = i(0,c) ^ multiply(i(1,c),2) ^ multiply(i(2,c),3) ^ i(3,c);
        s(2,c) = i(0,c) ^ i(1,c) ^ multiply(i(2,c),2) ^ multiply(i(3,c),3);
        s(3,c) = multiply(i(0,c),3) ^ i(1,c) ^ i(2,c) ^ multiply(i(3,c),2);
    }
}

// Function used in the Key Expansion routine takes a word [a0,a1,a2,a3] as input,
// performs a cyclic permutation, and returns the word [a1,a2,a3,a0].
void RotWord(uint8_t* word) {
    auto a0 = word[0];
    auto a1 = word[1];
    auto a2 = word[2];
    auto a3 = word[3];
    word[0] = a1;
    word[1] = a2;
    word[2] = a3;
    word[3] = a0;
}

// Transformation in the Cipher that processes the State by cyclically
// shifting the last three rows of the State by different offsets
void ShiftRows(state& s) {
    const auto i = s; // Copy input
    for (unsigned row = 0; row < 4; ++row) {
        for (unsigned col = 0; col < Nb; ++col) {
            s(row, col) = i(row, (col+row) % Nb);
        }
    }
}

static const uint8_t s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

// Transformation in the Cipher that processes the State using a nonlinear
// byte substitution table (S-box) that operates on each of the State bytes independently
void SubBytes(state& s) {
    for (auto& b : s) {
        b = s_box[b];
    }
}

// Function used in the Key Expansion routine that takes a four-byte
// input word and applies an S-box to each of the four bytes to produce an output word
void SubWord(uint8_t* word) {
    for (unsigned i = 0; i < 4; ++i) {
        word[i] = s_box[word[i]];
    }
}

// 5.2 Key Expansion

std::vector<uint8_t> KeyExpansion(const std::vector<uint8_t>& key) // KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
{
    const unsigned Nk = Nk_from_size(key.size());
    const unsigned Nr = Nr_from_Nk(Nk);
    std::vector<uint8_t> w(Nb*(Nr+1)*4); // out

    uint8_t temp[4]; // word temp

    unsigned i = 0;  // i = 0

    while (i < Nk) { // while (i < Nk)
        // w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
        for (int j=0;j<4;++j) w[i*4+j] = key[i*4+j];
        ++i; // i = i+1
    } // end while
    // i = Nk

//#define P(t,x) do { std::cout << t << " " << util::base16_encode(&(x),4) << " "; } while (0)
#define P(t,x)

    uint16_t x = 1;
    while (i < Nb * (Nr+1)) { // while (i < Nb * (Nr+1)]
        //std::cout << "i=" << std::setw(2) << i << " ";
        // temp = w[i-1]
        for (int j=0;j<4;++j) temp[j] = w[(i-1)*4+j];
        P("temp", temp);
        if (i % Nk == 0) { // if (i mod Nk = 0)
            //temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
            RotWord(temp);
            P("After RotWord", temp);
            SubWord(temp);
            P("After SubWord", temp);
            assert(i/Nk < 32);
            assert(x <= 0xff);
            uint8_t rcon[4] = { static_cast<uint8_t>(x), 0x00, 0x00, 0x00 }; // Rcon[i/Nk]
            x = multiply(x, 2);
            P("Rcon[i/Nk]", rcon);
            for (int j=0;j<4;++j) temp[j] = temp[j] ^ rcon[j];
            P("After XOR", temp);
        } else if (Nk > 6 && i % Nk == 4) { // else if (Nk > 6 and i mod Nk = 4)
            SubWord(temp); // temp = SubWord(temp)
            P("After SubWord",temp);
        } // end if
        // w[i] = w[i-Nk] xor temp
        for (int j=0;j<4;++j) w[i*4+j] = w[(i-Nk)*4+j] ^ temp[j];
        P("w[i]",w[i*4]);
        ++i; // i = i+1
        //std::cout << std::endl;
    } // end while
#undef P
    return w;
} // end

} // unnamed namespace
