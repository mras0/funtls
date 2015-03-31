#include "aes.h"

#include <cassert>

#include <util/test.h>

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

// Addition is XOR
//
// In the polynomial representation, multiplication in GF(2^8) [...] corresponds with the
// multiplication of polynomials modulo an irreducible polynomial of degree 8. A polynomial is
// irreducible if its only divisors are one and itself. For the AES algorithm, this irreducible
// polynomial is m(x) = x^8 + x^4 + x^3 + x + 1 or [0x11b] in hexadecimal notation

namespace {

// K Cipher Key
// Rcon[] The round constant word array. 
// Nb Number of columns (32-bit words) comprising the State. For this
// standard, Nb = 4. (Also see Sec. 6.3.)
// Nk Number of 32-bit words comprising the Cipher Key. For this
// standard, Nk = 4, 6, or 8. (Also see Sec. 6.3.)
// Nr Number of rounds, which is a function of Nk and Nb (which is
// fixed). For this standard, Nr = 10, 12, or 14. (Also see Sec. 6.3.)


// Transformation in the Cipher and Inverse Cipher in which a Round
// Key is added to the State using an XOR operation. The length of a
// Round Key equals the size of the State (i.e., for Nb = 4, the Round
// Key length equals 128 bits/16 bytes)
void AddRoundKey() {
    assert(!"Not implemented");
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
void MixColumns() {
    assert(!"Not implemented");
}

// Function used in the Key Expansion routine that takes a four-byte word 
// and performs a cyclic permutation
void RotWord() {
    assert(!"Not implemented");
}

// Transformation in the Cipher that processes the State by cyclically
// shifting the last three rows of the State by different offsets
void ShiftRows() {
    assert(!"Not implemented");
}

// Transformation in the Cipher that processes the State using a nonlinear
// byte substitution table (S-box) that operates on each of the State bytes independently
void SubBytes() {
    assert(!"Not implemented");
}

// Function used in the Key Expansion routine that takes a four-byte
// input word and applies an S-box to each of the four bytes to produce an output word
void SubWord() {
    assert(!"Not implemented");
}

} // unnamed namespace

namespace funtls { namespace aes {

//For the AES algorithm, the length of the Cipher Key, K, is 128, 192, or 256 bits. The key
//length is represented by Nk = 4, 6, or 8, which reflects the number of 32-bit words (number of
//columns) in the Cipher Key.
//For the AES algorithm, the number of rounds to be performed during the execution of the
//algorithm is dependent on the key size. The number of rounds is represented by Nr, where Nr =
//10 when Nk = 4, Nr = 12 when Nk = 6, and Nr = 14 when Nk = 8. 

std::vector<uint8_t> aes_128_ecb(const std::vector<uint8_t>& key, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(key.size(), ==, 16, "Key must be 128-bit");
    FUNTLS_CHECK_BINARY(input.size(), ==, 16, "input must be 128-bit (for now)");
    return {};
}

} } // namespace funtls::aes
