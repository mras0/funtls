#ifndef FUNTLS_X509_X509_RSA_H_INCLUDED
#define FUNTLS_X509_X509_RSA_H_INCLUDED

#include <x509/x509.h>
#include <memory>
#include <cassert>
#include <vector>

namespace funtls { namespace x509 {

struct rsa_public_key {
    asn1::integer modulus;           // n
    asn1::integer public_exponent;   // e

    size_t key_length() const {
        size_t k = modulus.octet_count(); // Length of modulus
        assert(k!=0);
        if (modulus.octet(0) == 0) {
            // The leading byte of the modulos was 0, discount it in calculating the
            // bit length
            k--;
            assert(k && (modulus.octet(1) & 0x80)); // The leading byte should only be 0 if the msb is set on the next byte
        }
        return k;
    }

    static rsa_public_key parse(const asn1::der_encoded_value& repr);
};

struct rsa_private_key {
    asn1::integer version;          // { two-prime(0), multi(1) }
    asn1::integer modulus;          // n
    asn1::integer public_exponent;  // e
    asn1::integer private_exponent; // d
    asn1::integer prime1;           // p
    asn1::integer prime2;           // q
    asn1::integer exponent1;        // d mod (p-1)
    asn1::integer exponent2;        // d mod (q-1)
    asn1::integer coefficient;      // (inverse of q) mod p
    // otherPrimeInfos   OtherPrimeInfos OPTIONAL

    static rsa_private_key parse(const asn1::der_encoded_value& repr);
};

struct digest_info {
    x509::algorithm_id      digest_algorithm;
    std::vector<uint8_t>    digest;
};

std::vector<uint8_t> pkcs1_decode(const rsa_private_key& key, const std::vector<uint8_t>& message);
digest_info pkcs1_decode(const rsa_public_key& pk, const std::vector<uint8_t>& data);
std::vector<uint8_t> pkcs1_encode(const rsa_private_key& key, const std::vector<uint8_t>& message);
std::vector<uint8_t> pkcs1_encode(const rsa_public_key& key, const std::vector<uint8_t>& message);

rsa_public_key rsa_public_key_from_certificate(const certificate& cert);
rsa_private_key rsa_private_key_from_pki(const private_key_info& pki);

void verify_x509_signature_rsa(const certificate& subject_cert, const certificate& issuer_cert);

} } // namespace funtls::x509

#endif
