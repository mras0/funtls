#ifndef INT_UTIL_INT_UTIL_H_INCLUDED
#define INT_UTIL_INT_UTIL_H_INCLUDED

#include <cassert>
#include <cstdlib>
#include <vector>
#include <util/random.h>
#include <stdint.h>

#ifndef USE_FUNTLS_BIGINT
#ifdef _MSC_VER
#pragma warning(disable: 4319) // C4319: '~': zero extending 'const unsigned long' to 'boost::multiprecision::double_limb_type' of greater size
#pragma warning(disable: 4193) // C4193 : #pragma warning(pop) : no matching '#pragma warning(push)'
#endif
#include <boost/multiprecision/miller_rabin.hpp>
#endif

namespace funtls {

template<typename a_expr, typename IntType>
IntType pmod(const a_expr& a, const IntType& p) {
    IntType res = a % p;
#ifndef USE_FUNTLS_BIGINT
    if (res < 0) res += p;
#endif
    assert(res >= 0 && res < p);
    return res;
}

template<typename a_expr, typename IntType>
IntType modular_inverse(const a_expr& a, const IntType& n)
{
    assert(n!=0);
    IntType r = n, newr = pmod(a, n);
    IntType t = 0, newt = 1;
    while (newr != 0) {
        IntType quotient = r / newr;
        IntType saved = newt;
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

template<typename a_expr, typename b_expr, typename IntType>
IntType div_mod(const a_expr& a, const b_expr& b, const IntType& n)
{
    return pmod(a * modular_inverse(b, n), n);
}

template<typename IntType>
IntType be_uint_from_bytes(const std::vector<uint8_t>& bytes)
{
    IntType res = 0;
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
    assert(i == 0);
    return result;
}


template<typename IntType>
size_t ilog256(IntType n)
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
IntType rand_int_less(const IntType& less_than) {
    assert(less_than != 0);
    const auto byte_count   = static_cast<uint32_t>(ilog256<IntType>(less_than - 1));
    const auto leading_byte = static_cast<uint8_t>(((less_than-1) >> (8*(byte_count-1))) & 0xff);

    uint8_t lead_byte_mask = 0xFF;
    while ((lead_byte_mask>>1) > leading_byte) {
        lead_byte_mask >>= 1;
    }
    assert(lead_byte_mask);

    assert(byte_count != 0);
    std::vector<uint8_t> bytes(byte_count);
    IntType res;
    int iter = 0;
    do {
        util::get_random_bytes(&bytes[0], bytes.size());
        bytes[0] &= lead_byte_mask;
        res = be_uint_from_bytes<IntType>(bytes);
        if (++iter > 1000) {
            assert(!"Internal error");
            std::abort();
        }
    } while (res >= less_than);
    return res;
}

template<typename IntType>
IntType rand_positive_int_in_interval(const IntType& no_less_than, const IntType& no_greater_equal_than) {
    assert(no_less_than + 1 < no_greater_equal_than && "Empty range");
    return no_less_than + rand_int_less<IntType>(no_greater_equal_than - no_less_than);
}

template<typename IntType>
IntType rand_positive_int_less(const IntType& n) {
    return rand_positive_int_in_interval<IntType>(1, n);
}

template<typename IntType>
bool is_prime(const IntType& n) {
    return miller_rabin_test(n, 25);
}


// TODO: This is unsafe. The boost multiprecision sample uses independent random generators for testing and number generation
// It's probably also terrible in other aspects
template<typename IntType>
IntType random_prime(const IntType& no_less_than, const IntType& no_greater_equal_than)
{
    constexpr int maxiter = 10000; // According to the prime number theorem we expect a random 4096-number to be prime with probability ~ 1/log(2**4096) ~ 1/3000
    for (int iter = 0; iter < maxiter; ++iter) {
        auto res = rand_positive_int_in_interval(no_less_than, no_greater_equal_than);
        if (miller_rabin_test(res, 25)) {
            return res;
        }
    }
    assert(!"Internal error: No prime generated within maxiter iterations");
    std::abort();
}

template<typename IntType>
IntType gcd(IntType a, IntType b) {
    for (;;) {
        if (b == 0) return a;
        IntType temp = a % b;
        a = b;
        b = temp;
    }
}


} // namespace funtls

#endif
