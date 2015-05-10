#include "x509_ec.h"
#include <util/test.h>
#include <util/base_conversion.h>
#include <ec/ec.h>
#include <hash/hash.h>

#include <cassert>
#include <iostream> // TEMP

using namespace funtls;

// Ref: http://www.cryptrec.go.jp/cryptrec_03_spec_cypherlist_files/PDF/01_01sec1.pdf

namespace {

std::vector<uint8_t> bit_to_octet_string(const asn1::bit_string& bs) {
    // Informally the idea is to pad the bit string with 0’s on the left
    // to make its length a multiple of 8, then chop the result up into octets.
    const auto bits = bs.bit_count();
    FUNTLS_CHECK_BINARY(bits, !=, 0, "Empty bit string");
    FUNTLS_CHECK_BINARY(bits&7, ==, 0, "Extra bits not yet supported");
    return bs.repr();
}

hash::hash_algorithm hash_from_ecdsa_signature_algo(const x509::algorithm_id& sig_algo)
{
    if (sig_algo.id() == x509::id_ecdsaWithSHA256) {
        return hash::sha256{};
    } else if (sig_algo.id() == x509::id_ecdsaWithSHA384) {
        return hash::sha384{};
    } else if (sig_algo.id() == x509::id_ecdsaWithSHA512) {
        return hash::sha512{};
    }
    std::ostringstream oss;
    oss << "Unknown ECDSA signature algorithm " << sig_algo;
    FUNTLS_CHECK_FAILURE(oss.str());
}

} // unnamed namespace

namespace funtls { namespace x509 {

const ec::curve& curve_from_name(const asn1::object_id& id) {
    if (id == x509::id_secp256r1) return ec::secp256r1;
    if (id == x509::id_secp384r1) return ec::secp384r1;

    std::ostringstream msg;
    msg << "Unsupported named elliptic curve: " << id;
    FUNTLS_CHECK_FAILURE(msg.str());
}

ecdsa_sig_value ecdsa_sig_value::parse(const asn1::der_encoded_value& repr) {
    auto seq = asn1::sequence_view{repr};
    auto r = asn1::integer{seq.next()};
    auto s = asn1::integer{seq.next()};
    FUNTLS_CHECK_BINARY(seq.has_next(), ==, false, "Invalid ECDSA signature");
    return {r.as<ec::field_elem>(), s.as<ec::field_elem>()};
}

ecdsa_sig_value ecdsa_sig_value::parse(const std::vector<uint8_t>& bytes) {
    util::buffer_view sig_view(bytes.data(), bytes.size());
    return ecdsa_sig_value::parse(asn1::read_der_encoded_value(sig_view));
}

ec_public_key ec_public_key_from_certificate(const certificate& cert)
{
    FUNTLS_CHECK_BINARY(cert.tbs().subject_public_key_algo.id(), ==, id_ecPublicKey, "Invalid algorithm");

    // Extract named curve parameter (only supported ECParameter type)
    FUNTLS_CHECK_BINARY(cert.tbs().subject_public_key_algo.null_parameters(), ==, false, "Invalid algorithm parameters");
    const auto curve_name = from_buffer<asn1::object_id>(cert.tbs().subject_public_key_algo.parameters());
    const auto Q          = ec::point_from_bytes(bit_to_octet_string(cert.tbs().subject_public_key));
    return {curve_name, Q};
}

// TODO: Lots of duplication of verify_x509_signature_rsa
void verify_x509_signature_ec(const certificate& subject_cert, const certificate& issuer_cert)
{
    auto issuer_pk = ec_public_key_from_certificate(issuer_cert);
    const auto& curve = curve_from_name(issuer_pk.curve_name);
    const auto& Q = issuer_pk.Q;
    curve.check_public_key(Q);

    FUNTLS_CHECK_BINARY(x509::id_ecPublicKey, ==, public_key_algo_from_signature_algo(subject_cert.signature_algorithm()), "Only RSA supported");
    FUNTLS_CHECK_BINARY(subject_cert.signature_algorithm(), ==, subject_cert.tbs().signature_algorithm, "Signature algorihtm mismatch");
    FUNTLS_CHECK_BINARY(subject_cert.tbs().issuer, ==, issuer_cert.tbs().subject, "Issuer certificate does not match");

    // Do Verifying operation per SEC1 4.1.4

    const auto sig = ecdsa_sig_value::parse(subject_cert.signature().as_vector());

    auto hash = hash_from_ecdsa_signature_algo(subject_cert.signature_algorithm());
    const auto H = hash.input(subject_cert.certificate_der_encoded()).result();
    const auto e  = x509::base256_decode<ec::field_elem>(H);

    curve.verify_ecdsa_signature(Q, sig.r, sig.s, e);
}

} } // namespace funtls::x509

