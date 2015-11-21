#include "win32_util.h"
#include <Windows.h>
#include <cassert>

namespace funtls { namespace util {

void win32_handle_closer::operator()(void* h) {
    const BOOL closed_ok = CloseHandle(h);
    assert(closed_ok); (void)closed_ok;
}

unsigned win32_get_last_error()
{
    return GetLastError();
}

void throw_system_error(const std::string& what, const unsigned error_code)
{
    assert(error_code != ERROR_SUCCESS);
    throw std::system_error(error_code, std::system_category(), what);
}


} } // namespace funtls::util