#ifndef FUNTLS_X509_X509_RSA_H_INCLUDED
#define FUNTLS_X509_X509_RSA_H_INCLUDED

#include <x509/x509.h>
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

void verify_x509_signature_rsa(const certificate& subject_cert, const certificate& issuer_cert);

} } // namespace funtls::x509

#endif
