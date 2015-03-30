#ifndef FUNTLS_X509_X509_RSA_H_INCLUDED
#define FUNTLS_X509_X509_RSA_H_INCLUDED

#include <x509/x509.h>
#include <memory>
#include <cassert>

namespace funtls { namespace x509 {

static const asn1::object_id rsaEncryption{ 1,2,840,113549,1,1,1 };
static const asn1::object_id sha256WithRSAEncryption{ 1,2,840,113549,1,1,11 };

struct rsa_public_key {
    asn1::integer modolus;           // n
    asn1::integer public_exponent;   // e

    static rsa_public_key parse(const asn1::der_encoded_value& repr);
};

rsa_public_key rsa_public_key_from_certificate(const v3_certificate& cert);

// Actually PKCS#1 RFC3447 stuff:

// TODO: Figure out something less ugly
template<typename IntType, typename Iterator>
IntType base256_decode(Iterator first, Iterator last)
{
    IntType res = 0;
    for (; first != last; ++first) {
        res <<= 8;
        res |= *first;
    }
    return res;
}

template<typename IntType, size_t sz>
IntType base256_decode(const uint8_t (&arr)[sz])
{
    return base256_decode<IntType>(arr, arr+sz);
}

template<typename IntType>
IntType base256_decode(const std::vector<uint8_t>& bs)
{
    return base256_decode<IntType>(bs.begin(), bs.end());
}

template<typename IntType>
IntType base256_decode(const asn1::raw_string& r)
{
    return base256_decode<IntType>(r.as_vector());
}

template<typename IntType>
std::vector<uint8_t> base256_encode(IntType i, size_t byte_count)
{
    std::vector<uint8_t> result(byte_count);
    while (byte_count--) {
        result[byte_count] = static_cast<uint8_t>(i);
        i >>= 8;
    }
    assert(!i);
    return result;
}


} } // namespace funtls::x509

#endif
