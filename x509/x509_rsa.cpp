#include "x509_rsa.h"
#include <util/test.h>
#include <util/base_conversion.h>
#include <util/buffer.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

#include <iostream>

namespace funtls { namespace x509 {

rsa_public_key rsa_public_key::parse(const asn1::der_encoded_value& repr)
{
    auto elem_seq        = asn1::sequence_view{repr};
    auto modolus         = funtls::asn1::integer(elem_seq.next());
    auto public_exponent = funtls::asn1::integer(elem_seq.next());
    FUNTLS_CHECK_BINARY(elem_seq.has_next(), ==, false, "Extra data at end of RSA public key");
    return rsa_public_key{modolus, public_exponent};
}

digest_info pkcs1_decode(const rsa_public_key& pk, const std::vector<uint8_t>& data)
{
    // The signatureValue field contains a digital signature computed upon
    // the ASN.1 DER encoded tbsCertificate.  The ASN.1 DER encoded
    // tbsCertificate is used as the input to the signature function.

    // See 9.2 EMSA-PKCS1-v1_5 in RFC3447

    // The encrypted signature is stored as a base-256 encoded number in the bitstring
    const auto sig_int  = x509::base256_decode<int_type>(data);
    const size_t em_len = data.size(); // encrypted message length
    FUNTLS_CHECK_BINARY(pk.key_length(), ==, em_len, "Invalid PKCS#1 1.5 signature");

    // Decode the signature using the issuers public key (here using the subjects PK since the cert is selfsigned)
    int_type d = powm(sig_int, pk.public_exponent.as<int_type>(), pk.modolus.as<int_type>());
    const auto decoded = x509::base256_encode(d, em_len);

    // EM = 0x00 || 0x01 || PS || 0x00 || T (T=DER encoded DigestInfo)
    auto digest_buf = util::buffer_view{&decoded[0], decoded.size()};
    FUNTLS_CHECK_BINARY(0x00, ==, digest_buf.get(), "Invalid PKCS#1 1.5 signature");
    FUNTLS_CHECK_BINARY(0x01, ==, digest_buf.get(), "Invalid PKCS#1 1.5 signature");
    // Skip padding
    for (;;) {
        const auto b = digest_buf.get();
        if (b == 0xff) { // Padding...
            continue;
        } else if (b == 0x00) { // End of padding
            break;
        } else {
            FUNTLS_CHECK_FAILURE("Invalid byte in PKCS#1 1.5 padding: 0x" + util::base16_encode(&b, 1));
        }
    }
    // DigestInfo ::= SEQUENCE {
    //   digestAlgorithm AlgorithmIdentifier,
    //   digest OCTET STRING }

    auto digest_info = asn1::sequence_view{asn1::read_der_encoded_value(digest_buf)};
    FUNTLS_CHECK_BINARY(digest_buf.remaining(), ==, 0, "Invalid PKCS#1 1.5 signature");

    auto digest_algo = x509::read_algorithm_identifer(digest_info.next());
    auto digest = asn1::octet_string{digest_info.next()}.as_vector();
    FUNTLS_CHECK_BINARY(digest_info.has_next(), ==, false, "Invalid PKCS#1 1.5 signature");

    return x509::digest_info{digest_algo, digest};
}

rsa_public_key rsa_public_key_from_certificate(const v3_certificate& cert)
{
    FUNTLS_CHECK_BINARY(cert.certificate().subject_public_key_algo, ==, rsaEncryption, "Unsupported public key algorithm");
    const auto vec = cert.certificate().subject_public_key.as_vector();
    util::buffer_view pk_buf{&vec[0], vec.size()};
    return x509::rsa_public_key::parse(asn1::read_der_encoded_value(pk_buf));
}

} } // namespace funtls::x509
