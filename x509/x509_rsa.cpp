#include "x509_rsa.h"
#include <util/test.h>
#include <util/base_conversion.h>
#include <util/buffer.h>
#include <util/random.h>
#include <hash/hash.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

namespace {

hash::hash_algorithm get_hash(const asn1::object_id& oid)
{
    if (oid == x509::id_md5) {
        return hash::md5{};
    } else if (oid == x509::id_sha1) {
        return hash::sha1{};
    } else if (oid == x509::id_sha256) {
        return hash::sha256{};
    } else if (oid == x509::id_sha384) {
        return hash::sha384{};
    } else if (oid == x509::id_sha512) {
        return hash::sha512{};
    }

    std::ostringstream oss;
    oss << "Unknown hash algorithm " << oid;
    FUNTLS_CHECK_FAILURE(oss.str());
}

asn1::object_id digest_algo_from_signature_algo(const x509::algorithm_id& sig_algo)
{
    if (public_key_algo_from_signature_algo(sig_algo) == x509::id_rsaEncryption) {
        FUNTLS_CHECK_BINARY(sig_algo.null_parameters(), ==, true, "Invalid algorithm parameters");
    }
    if (sig_algo.id() == x509::id_md5WithRSAEncryption) {
        return x509::id_md5;
    } else if (sig_algo.id() == x509::id_sha1WithRSAEncryption) {
        return x509::id_sha1;
    } else if (sig_algo.id() == x509::id_sha256WithRSAEncryption) {
        return x509::id_sha256;
    } else if (sig_algo.id() == x509::id_sha384WithRSAEncryption) {
        return x509::id_sha384;
    } else if (sig_algo.id() == x509::id_sha512WithRSAEncryption) {
        return x509::id_sha512;
    }
    std::ostringstream oss;
    oss << "Unknown signature algorithm " << sig_algo;
    FUNTLS_CHECK_FAILURE(oss.str());
}

} // unnamed namespace

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
    FUNTLS_CHECK_BINARY(pk.key_length() & (pk.key_length()-1), ==, 0, "Non pow2 key length? " + std::to_string(pk.key_length()));
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
    FUNTLS_CHECK_BINARY(0x00, ==, static_cast<unsigned>(digest_buf.get()), "Invalid PKCS#1 1.5 signature");
    FUNTLS_CHECK_BINARY(0x01, ==, static_cast<unsigned>(digest_buf.get()), "Invalid PKCS#1 1.5 signature");
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

    auto digest_algo = x509::algorithm_id(digest_info.next());
    auto digest = asn1::octet_string{digest_info.next()}.as_vector();
    FUNTLS_CHECK_BINARY(digest_info.has_next(), ==, false, "Invalid PKCS#1 1.5 signature");

    return x509::digest_info{digest_algo, digest};
}

std::vector<uint8_t> pkcs1_encode(const x509::rsa_public_key& key, const std::vector<uint8_t>& message)
{
    FUNTLS_CHECK_BINARY(key.key_length() & (key.key_length()-1), ==, 0, "Non pow2 key length?");
    const auto n = key.modolus.as<int_type>();
    const auto e = key.public_exponent.as<int_type>();

    // Perform RSAES-PKCS1-V1_5-ENCRYPT (http://tools.ietf.org/html/rfc3447 7.2.1)

    // Get k=message length
    const size_t k = key.key_length();

    // Build message to encrypt: EM = 0x00 || 0x02 || PS || 0x00 || M
    std::vector<uint8_t> EM(k-message.size());
    EM[0] = 0x00;
    EM[1] = 0x02;
    // PS = at least 8 pseudo random characters (must be non-zero for type 0x02)
    util::get_random_bytes(&EM[2], EM.size()-3);
    for (size_t i = 2; i < EM.size()-1; ++i) {
        while (!EM[i]) {
            util::get_random_bytes(&EM[i], 1);
        }
    }
    EM[EM.size()-1] = 0x00;
    // M = message to encrypt
    EM.insert(EM.end(), std::begin(message), std::end(message));
    assert(EM.size()==k);

    // 3.a
    const auto m = x509::base256_decode<int_type>(EM); // m = OS2IP (EM)
    assert(m < n); // Is the message too long?
    //std::cout << "m (" << EM.size() << ") = " << util::base16_encode(EM) << std::dec << "\n";

    // 3.b
    const int_type c = powm(m, e, n); // c = RSAEP ((n, e), m)
    //std::cout << "c:\n" << c << std::endl;

    // 3.c Convert the ciphertext representative c to a ciphertext C of length k octets
    // C = I2OSP (c, k)
    const auto C = x509::base256_encode(c, k);
    //std::cout << "C:\n" << util::base16_encode(C) << std::endl;

    return C;
}

rsa_public_key rsa_public_key_from_certificate(const certificate& cert)
{
    FUNTLS_CHECK_BINARY(cert.tbs().subject_public_key_algo.id(), ==, id_rsaEncryption, "Invalid algorithm");
    FUNTLS_CHECK_BINARY(cert.tbs().subject_public_key_algo.null_parameters(), ==, true, "Invalid algorithm parameters");
    const auto vec = cert.tbs().subject_public_key.as_vector();
    util::buffer_view pk_buf{&vec[0], vec.size()};
    return x509::rsa_public_key::parse(asn1::read_der_encoded_value(pk_buf));
}

void verify_x509_signature_rsa(const certificate& subject_cert, const certificate& issuer_cert)
{
    auto c = subject_cert.tbs();
    FUNTLS_CHECK_BINARY(x509::id_rsaEncryption, ==, public_key_algo_from_signature_algo(subject_cert.signature_algorithm()), "Only RSA supported");
    FUNTLS_CHECK_BINARY(subject_cert.signature_algorithm(), ==, subject_cert.tbs().signature_algorithm, "Signature algorihtm mismatch");

    FUNTLS_CHECK_BINARY(c.issuer, ==, issuer_cert.tbs().subject, "Issuer certificate does not match");

    const auto digest_algo = digest_algo_from_signature_algo(subject_cert.signature_algorithm());

    // Decode the signature using the issuers public key
    auto digest = x509::pkcs1_decode(rsa_public_key_from_certificate(issuer_cert), subject_cert.signature().as_vector());
    FUNTLS_CHECK_BINARY(digest.digest_algorithm.null_parameters(), ==, true, "Invalid digest algorithm parameters");
    FUNTLS_CHECK_BINARY(digest.digest_algorithm.id(), ==, digest_algo, "Digest algorithm mismatch");

    const auto computed_sig = get_hash(digest_algo).input(subject_cert.certificate_der_encoded()).result();
    if (digest.digest != computed_sig) {
        std::ostringstream oss;
        oss << "Invalid certificate signature (algorithm = " << subject_cert.signature_algorithm() << ")\n";
        oss << "Computed:  " << util::base16_encode(computed_sig) << "\n";
        oss << "Signature: " << util::base16_encode(digest.digest);
        FUNTLS_CHECK_FAILURE(oss.str());
    }
}

} } // namespace funtls::x509
