#ifndef FUNTLS_UTIL_WIN32_UTIL_H_INCLUDED
#define FUNTLS_UTIL_WIN32_UTIL_H_INCLUDED

#include <memory>
#include <string>

namespace funtls { namespace util {

struct win32_handle_closer {
    void operator()(void* h);
};
using win32_handle = std::unique_ptr<void, win32_handle_closer>;

unsigned win32_get_last_error();

void throw_system_error(const std::string& what, const unsigned error_code = win32_get_last_error());

} } // namespace funtls::util

#endif