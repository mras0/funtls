#ifndef INT_UTIL_INT_H_INCLUDED
#define INT_UTIL_INT_H_INCLUDED

#ifdef USE_FUNTLS_BIGINT
#include <bigint/bigint.h>
#else
#ifdef _MSC_VER
#pragma warning(disable: 4319) // C4319: '~': zero extending 'const unsigned long' to 'boost::multiprecision::double_limb_type' of greater size
#endif
#include <boost/multiprecision/cpp_int.hpp>
#endif
namespace funtls {
#ifdef USE_FUNTLS_BIGINT
using large_uint = funtls::bigint::biguint;
#else
using large_uint = boost::multiprecision::cpp_int;
#endif

} // namespace funtls

#endif
