#ifndef FUNTLS_X509_X509_RSA_H_INCLUDED
#define FUNTLS_X509_X509_RSA_H_INCLUDED

#include <x509/x509.h>
#include <memory>
#include <cassert>
#include <vector>

namespace funtls { namespace x509 {

struct rsa_private_key {
    static const asn1::integer version_two_prime;
    
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

    void serialize(std::vector<uint8_t>& buf) const;

    static rsa_private_key parse(const asn1::der_encoded_value& repr);
    static rsa_private_key generate(unsigned bit_count);
};

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

    void serialize(std::vector<uint8_t>& buf) const;

    static rsa_public_key from_private(const rsa_private_key& k) {
        return {k.modulus, k.public_exponent};
    }

    static rsa_public_key parse(const asn1::der_encoded_value& repr);
};

class digest_info {
public:
    digest_info(const x509::algorithm_id& digest_algorithm, std::vector<uint8_t> digest) : digest_algorithm_(digest_algorithm), digest_(digest) {
    }

    const x509::algorithm_id& digest_algorithm() const { return digest_algorithm_; }
    const std::vector<uint8_t>& digest() const { return digest_; }

    void serialize(std::vector<uint8_t>& buf) const;

    static digest_info parse(const asn1::der_encoded_value& repr);

private:
    x509::algorithm_id      digest_algorithm_;
    std::vector<uint8_t>    digest_;
};

std::vector<uint8_t> pkcs1_decode(const rsa_private_key& key, const std::vector<uint8_t>& message);
digest_info pkcs1_decode(const rsa_public_key& pk, const std::vector<uint8_t>& data);

std::vector<uint8_t> pkcs1_encode(const rsa_private_key& key, const std::vector<uint8_t>& message);
std::vector<uint8_t> pkcs1_encode(const rsa_public_key& key, const std::vector<uint8_t>& message);

rsa_public_key rsa_public_key_from_certificate(const certificate& cert);
rsa_private_key rsa_private_key_from_pki(const private_key_info& pki);

void verify_x509_signature_rsa(const certificate& subject_cert, const certificate& issuer_cert);

private_key_info make_private_key_info(const rsa_private_key& private_key);

} } // namespace funtls::x509

#endif
