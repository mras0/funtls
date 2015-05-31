#include "poly1305.h"
#include <util/test.h>
#include <string.h>

#ifdef USE_FUNTLS_BIGINT
#include <bigint/bigint.h>
using int_type = funtls::bigint::biguint;
#else
#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;
#endif

namespace {
void append_le_bytes(int_type& res, const uint8_t* n, size_t size = 16)
{
    while (size--) {
        res <<= 8;
        res |= n[size];
    }
}

const int_type r_clamp_mask("0x0ffffffc0ffffffc0ffffffc0fffffff");
const int_type P("0x3fffffffffffffffffffffffffffffffb"); // 2^130-5
}

namespace funtls { namespace poly1305 {

std::vector<uint8_t> poly1305(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message)
{
    FUNTLS_CHECK_BINARY(key.size(), ==, key_length_bytes, "Invalid key length. Must be 32 bytes.");

    // Partition the key in to two parts
    int_type r = 0, s = 0;
    append_le_bytes(r, &key[0]);
    r &= r_clamp_mask;
    append_le_bytes(s, &key[16]);
#ifdef TESTING_POLY1305
    std::cout << "r " << std::hex << r << std::endl;
    std::cout << "s " << std::hex << s << std::endl;
#endif

    int_type accumulator = 0;

    // Divide the message into 16-byte blocks
    for (size_t i = 0; i < message.size(); i += block_length_bytes) {
        const size_t this_block = std::min(message.size() - i, block_length_bytes);

        // Read the block as a little-endian number
        // Add one bit beyond the number of octets.
        int_type n = 1;
        append_le_bytes(n, &message[i], this_block);

        accumulator += n;
#ifdef TESTING_POLY1305
        std::cout << "n " << std::hex << n << std::endl;
        std::cout << "accumulator " << std::hex << accumulator << std::endl;
#endif

        accumulator = (r * accumulator) % P;
#ifdef TESTING_POLY1305
        std::cout << "n " << std::hex << n << std::endl;
        std::cout << "accumulator " << std::hex << accumulator << std::endl;
#endif
    }
    accumulator += s;
#ifdef TESTING_POLY1305
    std::cout << "accumulator " << std::hex << accumulator << std::endl;
#endif

    std::vector<uint8_t> result(16);
    for (int i = 0; i < 16; ++i) {
        result[i] = static_cast<uint8_t>(accumulator);
        accumulator >>= 8;
    }
    return result;
}

} } // namespace funtls::poly1305
