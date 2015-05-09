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

ec::point parse_ec_point(const std::vector<uint8_t>& in) {
    FUNTLS_CHECK_BINARY(in.size(), >, 0, "Empty elliptic curve point");
    const auto type = in[0];
    if (type == 0) {
        // Curve point at infinity
        FUNTLS_CHECK_BINARY(in.size(), ==, 1, "Illegal elliptic curve point");
        return ec::infinity;
    } else if (type == 4) {
        FUNTLS_CHECK_BINARY((in.size()-1) & 1, ==, 0, "Illegal elliptic curve point");
        const auto beg = &in[1];
        const auto mid = &in[1+(in.size()-1)/2];
        const auto end = &in[in.size()];
        const std::vector<uint8_t> x(beg, mid);
        const std::vector<uint8_t> y(mid, end);
        assert(x.size() == y.size());
        auto res = ec::point{x509::base256_decode<ec::field_elem>(x), x509::base256_decode<ec::field_elem>(y)};
        assert(res != ec::infinity);
        return res;
    } else {
        FUNTLS_CHECK_FAILURE("Unsupported elliptic curve type " + std::to_string(type));
    }
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

const ec::curve& curve_from_name(const asn1::object_id& id) {
    if (id == x509::id_secp256r1) return ec::secp256r1;
    if (id == x509::id_secp384r1) return ec::secp384r1;

    std::ostringstream msg;
    msg << "Unsupported named elliptic curve: " << id;
    FUNTLS_CHECK_FAILURE(msg.str());
}

} // unnamed namespace

namespace funtls { namespace x509 {

struct ec_public_key {
    asn1::object_id curve_name;
    ec::point       Q; // public key (== d * curve.G, where d is the private key)
};

struct ecdsa_sig_value {
    asn1::integer r;
    asn1::integer s;

    static ecdsa_sig_value parse(const asn1::der_encoded_value& repr) {
        auto seq = asn1::sequence_view{repr};
        auto r = asn1::integer{seq.next()};
        auto s = asn1::integer{seq.next()};
        FUNTLS_CHECK_BINARY(seq.has_next(), ==, false, "Invalid ECDSA signature");
        return {std::move(r), std::move(s)};
    }
};

ec_public_key ec_public_key_from_certificate(const certificate& cert)
{
    FUNTLS_CHECK_BINARY(cert.tbs().subject_public_key_algo.id(), ==, id_ecPublicKey, "Invalid algorithm");

    // Extract named curve parameter (only supported ECParameter type)
    FUNTLS_CHECK_BINARY(cert.tbs().subject_public_key_algo.null_parameters(), ==, false, "Invalid algorithm parameters");
    const auto curve_name = from_buffer<asn1::object_id>(cert.tbs().subject_public_key_algo.parameters());
    const auto Q          = parse_ec_point(bit_to_octet_string(cert.tbs().subject_public_key));
    return {curve_name, Q};
}

// TODO: Lots of duplication of verify_x509_signature_rsa
void verify_x509_signature_ec(const certificate& subject_cert, const certificate& issuer_cert)
{
    std::cout << subject_cert << std::endl;
    std::cout << issuer_cert << std::endl;
    auto issuer_pk = ec_public_key_from_certificate(issuer_cert);
    const auto& curve = curve_from_name(issuer_pk.curve_name);
    curve.check();
    const auto& Q = issuer_pk.Q;
    std::cout << "public key " << Q << std::endl;
    // Verify elliptic curve public key (SEC1 3.2.2.1)
    FUNTLS_CHECK_BINARY(Q, !=, ec::infinity, "Invalid public key");
    FUNTLS_CHECK_BINARY(curve.on_curve(Q), ==, true, "Public key point not on named elliptic curve");
    FUNTLS_CHECK_BINARY(curve.mul(curve.n, Q), ==, ec::infinity, "Invalid public key");


    FUNTLS_CHECK_BINARY(x509::id_ecPublicKey, ==, public_key_algo_from_signature_algo(subject_cert.signature_algorithm()), "Only RSA supported");
    FUNTLS_CHECK_BINARY(subject_cert.signature_algorithm(), ==, subject_cert.tbs().signature_algorithm, "Signature algorihtm mismatch");
    FUNTLS_CHECK_BINARY(subject_cert.tbs().issuer, ==, issuer_cert.tbs().subject, "Issuer certificate does not match");

    const auto sig_buf = subject_cert.signature().as_vector();
    util::buffer_view sig_buf_view(sig_buf.data(), sig_buf.size());
    const auto sig = ecdsa_sig_value::parse(asn1::read_der_encoded_value(sig_buf_view));

    // Do Verifying operation per SEC1 4.1.4

    auto hash = hash_from_ecdsa_signature_algo(subject_cert.signature_algorithm());
    const auto H = hash.input(subject_cert.certificate_der_encoded()).result();

    const auto r = sig.r.as<ec::field_elem>();
    const auto s = sig.s.as<ec::field_elem>();
    FUNTLS_CHECK_BINARY(r, >=, 1, "Invalid ECDSA Signature");
    FUNTLS_CHECK_BINARY(r, <, curve.n, "Invalid ECDSA Signature");
    FUNTLS_CHECK_BINARY(s, >=, 1, "Invalid ECDSA Signature");
    FUNTLS_CHECK_BINARY(s, <, curve.n, "Invalid ECDSA Signature");

    const auto e  = x509::base256_decode<ec::field_elem>(H);
    const auto u1 = ec::div_mod(e, s, curve.n);
    const auto u2 = ec::div_mod(r, s, curve.n);
    std::cout << "e  " << e << std::endl;
    std::cout << "u1 " << u1 << std::endl;
    std::cout << "u2 " << u1 << std::endl;
    // R = (xR, yR) = u1 * G + u2 * Q
    const auto R = curve.add(curve.mul(u1, curve.G), curve.mul(u2, Q));
    std::cout << "R = " << R << std::endl;
    std::cout << "r   " << r << std::endl;
    FUNTLS_CHECK_BINARY(R, !=, ec::infinity, "Signature invalid");
    FUNTLS_CHECK_BINARY(R.x % curve.n, ==, r, "Signature mismatch");
}

} } // namespace funtls::x509

