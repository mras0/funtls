#ifndef INT_UTIL_INT_UTIL_H_INCLUDED
#define INT_UTIL_INT_UTIL_H_INCLUDED

#include <cassert>
#include <vector>
#include <util/random.h>
#include <stdint.h>

#ifndef USE_FUNTLS_BIGINT
#include <boost/multiprecision/miller_rabin.hpp>
#endif

namespace funtls {

template<typename a_expr, typename int_type>
int_type pmod(const a_expr& a, const int_type& p) {
    int_type res = a % p;
#ifndef USE_FUNTLS_BIGINT
    if (res < 0) res += p;
#endif
    assert(res >= 0 && res < p);
    return res;
}

template<typename a_expr, typename int_type>
int_type modular_inverse(const a_expr& a, const int_type& n)
{
    assert(n!=0);
    int_type r = n, newr = pmod(a, n);
    int_type t = 0, newt = 1;
    while (newr != 0) {
        int_type quotient = r / newr;
        int_type saved = newt;
        newt = pmod(quotient * saved, n);
        if (t < newt) t += n;
        assert(t>=newt);
        newt = t - newt;
        t = saved;
        saved = newr;
        newr = quotient * saved;
        assert(r>=newr);
        newr = r - newr;
        r = saved;
    }
    assert(r <= 1);
    assert(t >= 0);
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
size_t ilog256(int_type n)
{
    assert(n >= 0);
    size_t size = 1;
    while (n > 255) {
        ++size;
        n >>= 8;
    }
    return size;
}

template<typename IntType>
IntType rand_positive_int_less(const IntType& n) {
    const auto byte_count = ilog256(n);
    assert(byte_count != 0);
    std::vector<uint8_t> bytes(byte_count);
    IntType res;
    do {
        util::get_random_bytes(&bytes[0], bytes.size());
        res = be_uint_from_bytes<IntType>(bytes);
    } while (res == 0 || res >= n);
    return res;
}

template<typename int_type>
bool is_prime(const int_type& n) {
    return miller_rabin_test(n, 25);
}

} // namespace funtls

#endif