#ifndef FUNTLS_UTIL_RANDOM_H_INCLUDED
#define FUNTLS_UTIL_RANDOM_H_INCLUDED

#include <stddef.h>

namespace funtls { namespace util {

void get_random_bytes(void* dest, size_t count);

} } // namespace funtls::util

#endif
