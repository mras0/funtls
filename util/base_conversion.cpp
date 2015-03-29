#include "base_conversion.h"
#include <cassert>
#include <stdexcept>

namespace {

char hexchar(uint8_t d)
{
    assert(d < 16);
    return d < 10 ? d + '0' : d + 'a' - 10;
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
        throw std::logic_error("Invalid length " + std::to_string(len) + " of base16 encoded string '" + std::string(buffer, len) + "'");
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

} } // namespace funtls::util
