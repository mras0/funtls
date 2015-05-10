#ifndef UTIL_INT_UTIL_H_INCLUDED
#define UTIL_INT_UTIL_H_INCLUDED

#include <boost/multiprecision/miller_rabin.hpp>
#include <cassert>
#include <vector>

namespace funtls {

template<typename a_expr, typename int_type>
int_type pmod(const a_expr& a, const int_type& p) {
    int_type res = a % p;
    if (res < 0) res += p;
    assert(res >= 0 && res < p);
    return res;
}

template<typename a_expr, typename int_type>
int_type modular_inverse(const a_expr& a, const int_type& n)
{
    int_type r = n, newr = pmod(a, n);
    int_type t = 0, newt = 1;
    while (newr) {
        int_type quotient = r / newr;
        int_type saved = newt;
        newt = t - quotient * saved;
        t = saved;
        saved = newr;
        newr = r - quotient * saved;
        r = saved;
    }
    assert(r <= 1);
    if (t < 0) t += n;
    assert(pmod(a*t, n) == 1);
    return t;
}

template<typename a_expr, typename b_expr, typename int_type>
int_type div_mod(const a_expr& a, const b_expr& b, const int_type& n)
{
    return pmod(a * modular_inverse(b, n), n);
}

template<typename int_type>
int_type be_uint_from_bytes(const std::vector<uint8_t>& bytes)
{
    int_type res = 0;
    for (const auto& byte : bytes ) {
        res <<= 8;
        res |= byte;
    }
    return res;
}

template<typename IntType>
std::vector<uint8_t> be_uint_to_bytes(IntType i, size_t byte_count)
{
    std::vector<uint8_t> result(byte_count);
    while (byte_count--) {
        result[byte_count] = static_cast<uint8_t>(i);
        i >>= 8;
    }
    assert(!i);
    return result;
}


template<typename int_type>
size_t ilog256(const int_type& n)
{
    assert(n >= 0);
    size_t size        = 1;
    while (n > (int_type(1)<<(8*size))) {
        ++size;
    }
    return size;
}

} // namespace funtls

#endif
