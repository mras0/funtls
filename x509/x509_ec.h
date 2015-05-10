#ifndef FUNTLS_X509_X509_EC_H_INCLUDED
#define FUNTLS_X509_X509_EC_H_INCLUDED

#include <x509/x509.h>
#include <ec/ec.h>

namespace funtls { namespace x509 {

static const asn1::object_id id_secp256r1{1,2,840,10045,3,1,7};
static const asn1::object_id id_secp384r1{1,3,132,0,34};

struct ec_public_key {
    asn1::object_id curve_name;
    ec::point       Q; // public key (== d * curve.G, where d is the private key)
};

struct ecdsa_sig_value {
    ec::field_elem r;
    ec::field_elem s;

    static ecdsa_sig_value parse(const asn1::der_encoded_value& repr);
    static ecdsa_sig_value parse(const std::vector<uint8_t>& bytes);
};

const ec::curve& curve_from_name(const asn1::object_id& id);
ec_public_key ec_public_key_from_certificate(const certificate& cert);
void verify_x509_signature_ec(const certificate& subject_cert, const certificate& issuer_cert);

} } // namespace funtls::x509

#endif
