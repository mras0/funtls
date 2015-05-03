#ifndef FUNTLS_X509_X509_RSA_H_INCLUDED
#define FUNTLS_X509_X509_RSA_H_INCLUDED

#include <x509/x509.h>
#include <hash/hash.h>
#include <memory>
#include <cassert>
#include <vector>

namespace funtls { namespace x509 {

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
    x509::algorithm_id      digest_algorithm;
    std::vector<uint8_t>    digest;
};

digest_info pkcs1_decode(const rsa_public_key& pk, const std::vector<uint8_t>& data);
std::vector<uint8_t> pkcs1_encode(const x509::rsa_public_key& key, const std::vector<uint8_t>& message, void (*get_random_bytes)(void*, size_t));

rsa_public_key rsa_public_key_from_certificate(const certificate& cert);

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

//
// Checks the signature of the X509 v3 certificate 'subject_cert' against the issuers certificate
// 'issuer_cert' (Note: ONLY against this issuer, i.e. the validity of the issuers certificate is
// NOT verified).
// NOTE: validaty dates are not yet checked
// Throws an exception if the verification failed.
//
void verify_x509_certificate(const certificate& subject_cert, const certificate& issuer_cert);

//
// Checks the trust chain backwards from the last element of 'chain' to the first
// Ending with a self-signed root certificate. NOTE: The chain must contain at least
// 2 elements.
// NOTE: validaty dates are not yet checked
//
void verify_x509_certificate_chain(const std::vector<certificate>& chain);

} } // namespace funtls::x509

#endif
