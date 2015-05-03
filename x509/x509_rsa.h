#ifndef FUNTLS_X509_X509_RSA_H_INCLUDED
#define FUNTLS_X509_X509_RSA_H_INCLUDED

#include <x509/x509.h>
#include <memory>
#include <cassert>
#include <vector>

namespace funtls { namespace x509 {

static const asn1::object_id rsaEncryption{1,2,840,113549,1,1,1};
static const asn1::object_id sha256WithRSAEncryption{1,2,840,113549,1,1,11};
static const asn1::object_id id_sha256{2,16,840,1,101,3,4,2,1};
static const asn1::object_id id_sha1{1,3,14,3,2,26};

struct rsa_public_key {
    asn1::integer modolus;           // n
    asn1::integer public_exponent;   // e

    size_t key_length() const {
        size_t k = modolus.octet_count(); // Length of modolus
        assert(k!=0);
        if (modolus.octet(0) == 0) {
            // The leading byte of the modulos was 0, discount it in calculating the
            // bit length
            k--;
            assert(k && (modolus.octet(1) & 0x80)); // The leading byte should only be 0 if the msb is set on the next byte
        }
        return k;
    }

    static rsa_public_key parse(const asn1::der_encoded_value& repr);
};

struct digest_info {
    asn1::object_id         digest_algorithm;
    std::vector<uint8_t>    digest;
};

digest_info pkcs1_decode(const rsa_public_key& pk, const std::vector<uint8_t>& data);
std::vector<uint8_t> pkcs1_encode(const x509::rsa_public_key& key, const std::vector<uint8_t>& message, void (*get_random_bytes)(void*, size_t));

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
