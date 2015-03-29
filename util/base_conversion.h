#ifndef FUNTLS_UTIL_BASE_CONVERSION_H_INCLUDED
#define FUNTLS_UTIL_BASE_CONVERSION_H_INCLUDED

#include <string>
#include <vector>

namespace funtls { namespace util {

std::string base16_encode(const void* buffer, size_t len);
std::string base16_encode(const std::vector<uint8_t>& v);

std::vector<uint8_t> base16_decode(const char* buffer, size_t len);
std::vector<uint8_t> base16_decode(const std::string& s);

std::string base64_encode(const void* buffer, size_t len);
std::string base64_encode(const std::vector<uint8_t>& v);

std::vector<uint8_t> base64_decode(const char* buffer, size_t len);
std::vector<uint8_t> base64_decode(const std::string& s);


} } // namespace funtls::util

#endif
