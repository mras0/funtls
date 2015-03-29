#include "base_conversion.h"
#include <cassert>
#include <stdexcept>

namespace {

char hexchar(uint8_t d)
{
    assert(d < 16);
    return d < 10 ? d + '0' : d + 'A' - 10;
}

uint8_t hexdigit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        throw std::runtime_error(std::string("Invalid hexdigit '") + c + "'");
    }
}

constexpr char base64_pad_char = '=';

char base64_char(uint8_t x)
{
    assert(x < 64);
    static const char base64_chars[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return base64_chars[x];
}

uint8_t base64_digit(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    } else if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    } else if (c >= '0' && c <= '9') {
        return c - '0' + 26*2;
    } else if (c == '+') {
        return 62;
    } else if (c == '/') {
        return 63;
    } else {
        throw std::runtime_error(std::string("Invalid base64 digit '") + c + "'");
    }
}

// Process a 4-character base64 encoded block looking only at in_size characters
// and producing the appropriate number of output bytes:
// in_size | bytes produced
// --------+---------------
//   2     |      1
//   3     |      2
//   4     |      3
template<size_t in_size>
void base64_block(uint8_t* out, const char* in)
{
    static_assert(in_size >= 2 && in_size <= 4, "");
    uint32_t val = base64_digit(in[0]) << 18;
    val |= base64_digit(in[1]) << 12;
    if (in_size > 2) {
        val |= base64_digit(in[2]) << 6;
        if (in_size > 3) {
            val |= base64_digit(in[3]);
        } else {
            assert(in[3] == base64_pad_char);
        }
    } else {
        assert(in[2] == base64_pad_char);
        assert(in[3] == base64_pad_char);
    }
    assert(val < 0x1000000);
    out[0] = val>>16;
    if (in_size > 2) {
        out[1] = val>>8;
        if (in_size > 3) {
            out[2] = val;
        } else {
            assert((val & 0xff) == 0);
        }
    } else {
        assert((val & 0xffff) == 0);
    }
}

} // unnamed namespace

namespace funtls { namespace util {

std::string base16_encode(const void* buffer, size_t len)
{
    const uint8_t* bytes = static_cast<const uint8_t*>(buffer);
    assert(len <= len*2);
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += hexchar(bytes[i] >> 4);
        result += hexchar(bytes[i] & 0xf);
    }
    return result;
}

std::string base16_encode(const std::vector<uint8_t>& v)
{
    if (v.empty()) {
        return "";
    }
    return base16_encode(&v[0], v.size());
}

std::vector<uint8_t> base16_decode(const char* buffer, size_t len)
{
    if (len % 2) {
        throw std::runtime_error("Invalid length " + std::to_string(len) + " of base16 encoded string '" + std::string(buffer, len) + "'");
    }
    std::vector<uint8_t> v(len/2);
    for (size_t i = 0; i < len; i+=2) {
        v[i/2] = (hexdigit(buffer[i]) << 4) | hexdigit(buffer[i+1]);
    }
    return v;
}

std::vector<uint8_t> base16_decode(const std::string& s)
{
    if (s.empty()) {
        return {};
    }
    return base16_decode(s.data(), s.length());
}

// https://tools.ietf.org/html/rfc4648
// The encoding process represents 24-bit groups of input bits as output
//    strings of 4 encoded characters.  Proceeding from left to right, a
//    24-bit input group is formed by concatenating 3 8-bit input groups.
//    These 24 bits are then treated as 4 concatenated 6-bit groups, each
//    of which is translated into a single character in the base 64
//    alphabet.

std::string base64_encode(const void* buffer, size_t len)
{
    if (len == 0) {
        return "";
    }

    const size_t num_24bit_groups = (len + 2)/3;
    const size_t outlength = num_24bit_groups * 4;
    std::string res;
    res.reserve(outlength);
    const uint8_t* in = static_cast<const uint8_t*>(buffer);
    while (len >= 3) {
        const uint32_t n = (in[0] << 16) | (in[1] << 8) | in[2];
        res += base64_char((n>>18)&0x3f);
        res += base64_char((n>>12)&0x3f);
        res += base64_char((n>>6)&0x3f);
        res += base64_char(n&0x3f);
        in  += 3;
        len -= 3;
    }
    if (len == 2) {
        const uint32_t n = (in[0] << 16) | (in[1] << 8);
        res += base64_char((n>>18)&0x3f);
        res += base64_char((n>>12)&0x3f);
        res += base64_char((n>>6)&0x3f);
        res += base64_pad_char;
    } else if (len == 1) {
        const uint32_t n = (in[0] << 16);
        res += base64_char((n>>18)&0x3f);
        res += base64_char((n>>12)&0x3f);
        res += base64_pad_char;
        res += base64_pad_char;
    } else {
        assert(len == 0);
    }
    assert(res.size() == outlength);
    return res;
}

std::string base64_encode(const std::vector<uint8_t>& v)
{
    if (v.empty()) {
        return "";
    }
    return base64_encode(&v[0], v.size());
}

std::vector<uint8_t> base64_decode(const char* buffer, size_t len)
{
    if (len == 0) {
        return {};
    }
    if (len % 4) {
        throw std::runtime_error("Invalid length " + std::to_string(len) + " of base64 encoded string '" + std::string(buffer, len) + "'");
    }

    std::vector<uint8_t> result(3*len/4);
    uint8_t* out = &result[0];
    // As long as we can't be processing padding
    while (len > 4) {
        base64_block<4>(out, buffer);
        buffer += 4;
        out += 3;
        len -= 4;
    }
    // Left over characters, could include padding
    // Three (legal) cases to consider:
    //   (1) No padding      -> produce 24 bits
    //   (2) 1 padding char  -> produce 16 bits
    //   (3) 2 padding chars -> produce 8 bits
    assert(len == 4);
    assert(result.size() >= 3);
    if (buffer[3] != base64_pad_char) {
        // Case (1)
        base64_block<4>(out, buffer);
    } else {
        // Case (2) or (3)
        if (buffer[2] != base64_pad_char) {
            // Case (2)
            base64_block<3>(out, buffer);
            result.erase(result.end()-1, result.end());
        } else {
            // Case (3)
            base64_block<2>(out, buffer);
            result.erase(result.end()-2, result.end());
        }
    }
    return result;
}

std::vector<uint8_t> base64_decode(const std::string& s) {
    if (s.empty()) {
        return {};
    }
    return base64_decode(s.data(), s.length());
}

} } // namespace funtls::util
