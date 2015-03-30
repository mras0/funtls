#include "x509_rsa.h"
#include <util/test.h>

namespace funtls { namespace x509 {

rsa_public_key rsa_public_key::parse(const asn1::der_encoded_value& repr)
{
    auto elem_seq        = asn1::sequence_view{repr};
    auto modolus         = funtls::asn1::integer(elem_seq.next());
    auto public_exponent = funtls::asn1::integer(elem_seq.next());
    FUNTLS_CHECK_BINARY(elem_seq.has_next(), ==, false, "Extra data at end of RSA public key");
    return rsa_public_key{modolus, public_exponent};
}

rsa_public_key rsa_public_key_from_certificate(const v3_certificate& cert)
{
    FUNTLS_CHECK_BINARY(cert.certificate().subject_public_key_algo, ==, rsaEncryption, "Unsupported public key algorithm");
    const auto vec = cert.certificate().subject_public_key.as_vector();
    util::buffer_view pk_buf{&vec[0], vec.size()};
    return x509::rsa_public_key::parse(asn1::read_der_encoded_value(pk_buf));
}

} } // namespace funtls::x509
