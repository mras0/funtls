#include "x509_rsa.h"
#include <util/test.h>
#include <util/base_conversion.h>
#include <util/buffer.h>
#include <util/random.h>
#include <int_util/int.h>
#include <int_util/int_util.h>
#include <hash/hash.h>

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

asn1::object_id digest_algo_from_signature_algo(const asn1::object_id& sig_algo_id)
{
    if (sig_algo_id == x509::id_md5WithRSAEncryption) {
        return x509::id_md5;
    } else if (sig_algo_id == x509::id_sha1WithRSAEncryption) {
        return x509::id_sha1;
    } else if (sig_algo_id == x509::id_sha256WithRSAEncryption) {
        return x509::id_sha256;
    } else if (sig_algo_id == x509::id_sha384WithRSAEncryption) {
        return x509::id_sha384;
    } else if (sig_algo_id == x509::id_sha512WithRSAEncryption) {
        return x509::id_sha512;
    }
    std::ostringstream oss;
    oss << "Unknown signature algorithm id " << sig_algo_id;
    FUNTLS_CHECK_FAILURE(oss.str());
}

} // unnamed namespace

namespace funtls { namespace x509 {

void rsa_private_key::serialize(std::vector<uint8_t>& buf) const
{
    asn1::serialize_sequence(buf, asn1::identifier::constructed_sequence,
        version,
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient
        );
}

void rsa_public_key::serialize(std::vector<uint8_t>& buf) const
{
    asn1::serialize_sequence(buf, asn1::identifier::constructed_sequence, modulus, public_exponent);
}

rsa_public_key rsa_public_key::parse(const asn1::der_encoded_value& repr)
{
    auto elem_seq        = asn1::sequence_view{repr};
    auto modolus         = funtls::asn1::integer(elem_seq.next());
    auto public_exponent = funtls::asn1::integer(elem_seq.next());
    FUNTLS_CHECK_BINARY(elem_seq.has_next(), ==, false, "Extra data at end of RSA public key");
    return rsa_public_key{modolus, public_exponent};
}

void digest_info::serialize(std::vector<uint8_t>& buf) const
{
    asn1::serialize_sequence(buf, asn1::identifier::constructed_sequence, digest_algorithm_, asn1::octet_string{digest_});
}

digest_info digest_info::parse(const asn1::der_encoded_value& repr)
{
    // DigestInfo ::= SEQUENCE {
    //   digestAlgorithm AlgorithmIdentifier,
    //   digest OCTET STRING }

    auto digest_info = asn1::sequence_view{repr};
    auto digest_algo = x509::algorithm_id(digest_info.next());
    auto digest = asn1::octet_string{digest_info.next()}.as_vector();
    FUNTLS_CHECK_BINARY(digest_info.has_next(), ==, false, "Invalid DigestInfo structure");
    return {digest_algo, digest};
}

digest_info pkcs1_decode(const rsa_public_key& pk, const std::vector<uint8_t>& data)
{
    FUNTLS_CHECK_BINARY(pk.key_length() & (pk.key_length()-1), ==, 0, "Non pow2 key length? " + std::to_string(pk.key_length()));
    // The signatureValue field contains a digital signature computed upon
    // the ASN.1 DER encoded tbsCertificate.  The ASN.1 DER encoded
    // tbsCertificate is used as the input to the signature function.

    // See 9.2 EMSA-PKCS1-v1_5 in RFC3447

    // The encrypted signature is stored as a base-256 encoded number in the bitstring
    const auto sig_int  = x509::base256_decode<large_uint>(data);
    const size_t em_len = data.size(); // encrypted message length
    FUNTLS_CHECK_BINARY(pk.key_length(), ==, em_len, "Invalid PKCS#1 1.5 signature");

    // Decode the signature using the issuers public key (here using the subjects PK since the cert is selfsigned)
    large_uint d = powm(sig_int, pk.public_exponent.as<large_uint>(), pk.modulus.as<large_uint>());
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

    return digest_info::parse(asn1::read_der_encoded_value(digest_buf));
}

std::vector<uint8_t> pkcs1_decode(const rsa_private_key& pk, const std::vector<uint8_t>& data)
{
    const auto n = pk.modulus.as<large_uint>();
    const auto e = pk.private_exponent.as<large_uint>();
    FUNTLS_CHECK_BINARY(data.size(), <=, ilog256(n), "Signature too large");
    const large_uint d = powm(x509::base256_decode<large_uint>(data), e, n);
    auto decoded = x509::base256_encode(d, data.size());
    // Build message to encrypt: EM = 0x00 || 0x02 || PS || 0x00 || M
    FUNTLS_CHECK_BINARY(decoded.size(), >=, 2 + 8 + 1, "Invalid PKCS#1 1.5 signature");
    FUNTLS_CHECK_BINARY(0x00, ==, static_cast<unsigned>(decoded[0]), "Invalid PKCS#1 1.5 signature");
    FUNTLS_CHECK_BINARY(0x02, ==, static_cast<unsigned>(decoded[1]), "Invalid PKCS#1 1.5 signature");
    unsigned pad_end = 2;
    while (pad_end < decoded.size() && decoded[pad_end]) {
        ++pad_end;
    }
    FUNTLS_CHECK_BINARY(pad_end, <, decoded.size(), "Invalid PKCS#1 1.5 signature");
    assert(decoded[pad_end] == 0);
    decoded.erase(decoded.begin(), decoded.begin()+pad_end+1);
    return decoded;
}

std::vector<uint8_t> pkcs1_encode(const rsa_private_key& key, const std::vector<uint8_t>& message)
{
    const auto n = key.modulus.as<large_uint>();
    const auto d = key.private_exponent.as<large_uint>();
    const size_t k = ilog256(n);

    FUNTLS_CHECK_BINARY(message.size() + 3, <=, k, "RSA private key too small for message.");

    std::vector<uint8_t> EM(k-message.size());
    EM[0] = 0x00;
    EM[1] = 0x01;
    for (size_t i = 2; i < EM.size()-1; ++i) {
        EM[i] = 0xFF;
    }
    EM[EM.size()-1] = 0x00;
    EM.insert(EM.end(), std::begin(message), std::end(message));
    assert(EM.size()==k);
    // 3.a
    const auto m = x509::base256_decode<large_uint>(EM); // m = OS2IP (EM)
    assert(m < n); // Is the message too long?
    // 3.b
    const large_uint c = powm(m, d, n);
    return x509::base256_encode(c, k);
}

std::vector<uint8_t> pkcs1_encode(const rsa_public_key& key, const std::vector<uint8_t>& message)
{
    FUNTLS_CHECK_BINARY(key.key_length() & (key.key_length()-1), ==, 0, "Non pow2 key length?");
    const auto n = key.modulus.as<large_uint>();
    const auto e = key.public_exponent.as<large_uint>();

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
    const auto m = x509::base256_decode<large_uint>(EM); // m = OS2IP (EM)
    assert(m < n); // Is the message too long?
    //std::cout << "m (" << EM.size() << ") = " << util::base16_encode(EM) << std::dec << "\n";

    // 3.b
    const large_uint c = powm(m, e, n); // c = RSAEP ((n, e), m)
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

rsa_private_key rsa_private_key::parse(const asn1::der_encoded_value& repr)
{
    asn1::sequence_view key_seq{repr};

    auto version = asn1::integer{key_seq.next()};
    FUNTLS_CHECK_BINARY(version.as<int>(), ==, 0, "Invalid version");

    asn1::integer n{key_seq.next()};
    asn1::integer e{key_seq.next()};
    asn1::integer d{key_seq.next()};
    asn1::integer p{key_seq.next()};
    asn1::integer q{key_seq.next()};
    asn1::integer e1{key_seq.next()};
    asn1::integer e2{key_seq.next()};
    asn1::integer c{key_seq.next()};

    FUNTLS_CHECK_BINARY(key_seq.has_next(), ==, false, "Extra data in RSA private key");

    return {version, n, e, d, p, q, e1, e2, c};
}

const asn1::integer rsa_private_key::version_two_prime{0};

rsa_private_key rsa_private_key::generate(unsigned bit_count)
{
    assert(bit_count > 0);

    // Check with: openssl rsa -check -inform pem -text -noout

    const large_uint public_exponent = 65537; // Use same public exponent as openssl
    large_uint prime1, prime2, modulus, private_exponent;

    for (int iter = 0; ; ++iter) {
        FUNTLS_CHECK_BINARY(iter, <, 10, "Couldn't generate private key");
        // 1. Choose two distinct prime numbers p and q.
        prime1 = random_prime(large_uint{1}<<((bit_count/2)-1), large_uint{1}<<(bit_count/2));
        assert(prime1 >= large_uint{1}<<(bit_count/2-1) && prime1 < (large_uint{1}<<(bit_count/2)));

        prime2 = random_prime<large_uint>((large_uint{1}<<(bit_count-1))/prime1 + 1, (((large_uint{1}<<bit_count)-1)/prime1)+1);

        // 2. Compute n = pq.
        modulus = prime1 * prime2;
        assert(modulus >= large_uint{1}<<(bit_count-1) && modulus < (large_uint{1}<<bit_count));

        // 3. Compute phi(n) = phi(p)phi(q) =  (p - 1)(q - 1) = n - (p + q - 1)
        const large_uint phi_n = modulus - (prime1 + prime2 - 1);

        // 4. Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
        if (gcd(public_exponent, phi_n) == 1) {
            // 5. Determine d as d == e^-1 (mod phi(n)); i.e., d is the multiplicative inverse of e (modulo phi(n)).
            private_exponent = modular_inverse(public_exponent, phi_n);
            FUNTLS_CHECK_BINARY(large_uint((public_exponent*private_exponent) % phi_n), ==, 1, "Bad private key generated");
            break;
        }

        assert(false); // How often does this happen?
    }

    const large_uint exponent1   = private_exponent % (prime1 - 1); // d mod (p-1)
    const large_uint exponent2   = private_exponent % (prime2 - 1); // d mod (q-1)
    const large_uint coefficient = modular_inverse(prime2, prime1);

    return rsa_private_key{
        version_two_prime,
        asn1::integer{modulus},
        asn1::integer{public_exponent},
        asn1::integer{private_exponent},
        asn1::integer{prime1},
        asn1::integer{prime2},
        asn1::integer{exponent1},
        asn1::integer{exponent2},
        asn1::integer{coefficient}
    };
}

rsa_private_key rsa_private_key_from_pki(const private_key_info& pki)
{
    FUNTLS_CHECK_BINARY(pki.version.as<int>(), ==, 0, "Unsupported private key version");
    FUNTLS_CHECK_BINARY(pki.algorithm.id(), ==, x509::id_rsaEncryption, "Invalid private key algorithm");
    FUNTLS_CHECK_BINARY(pki.algorithm.null_parameters(), ==, true, "Invalid private key algorithm parameters");

    auto key_data = pki.key.as_vector();
    util::buffer_view key_buf(key_data.data(), key_data.size());
    auto pkey = rsa_private_key::parse(asn1::read_der_encoded_value(key_buf));
    FUNTLS_CHECK_BINARY(key_buf.remaining(), ==, 0, "Extra data in RSA private key");
    return pkey;
}

void verify_x509_signature_rsa(const certificate& subject_cert, const certificate& issuer_cert)
{
    auto c = subject_cert.tbs();
    FUNTLS_CHECK_BINARY(x509::id_rsaEncryption, ==, public_key_algo_from_signature_algo(subject_cert.signature_algorithm()), "Only RSA supported");
    FUNTLS_CHECK_BINARY(subject_cert.signature_algorithm(), ==, subject_cert.tbs().signature_algorithm, "Signature algorihtm mismatch");

    FUNTLS_CHECK_BINARY(c.issuer, ==, issuer_cert.tbs().subject, "Issuer certificate does not match");

    const auto sig_algo = subject_cert.signature_algorithm();
    if (public_key_algo_from_signature_algo(sig_algo) == x509::id_rsaEncryption) {
        FUNTLS_CHECK_BINARY(sig_algo.null_parameters(), ==, true, "Invalid algorithm parameters");
    }
    const auto digest_algo = digest_algo_from_signature_algo(sig_algo.id());

    // Decode the signature using the issuers public key
    auto digest = x509::pkcs1_decode(rsa_public_key_from_certificate(issuer_cert), subject_cert.signature().as_vector());
    FUNTLS_CHECK_BINARY(digest.digest_algorithm().null_parameters(), ==, true, "Invalid digest algorithm parameters");
    FUNTLS_CHECK_BINARY(digest.digest_algorithm().id(), ==, digest_algo, "Digest algorithm mismatch");

    const auto computed_sig = get_hash(digest_algo).input(subject_cert.certificate_der_encoded()).result();
    if (digest.digest() != computed_sig) {
        std::ostringstream oss;
        oss << "Invalid certificate signature (algorithm = " << subject_cert.signature_algorithm() << ")\n";
        oss << "Computed:  " << util::base16_encode(computed_sig) << "\n";
        oss << "Signature: " << util::base16_encode(digest.digest());
        FUNTLS_CHECK_FAILURE(oss.str());
    }
}

private_key_info make_private_key_info(const rsa_private_key& private_key)
{
    return {
        asn1::integer{0}, // version
        algorithm_id{id_rsaEncryption},
        asn1::octet_string{asn1::serialized(private_key)}
    };
}

class rsa_certificate_signer::impl  {
public:
    impl(const asn1::object_id& algorithm_id, const rsa_private_key& private_key)
        : algo_id_(algorithm_id)
        , private_key_(private_key) {
    }

    x509::certificate_signer::sign_result_t sign(const std::vector<uint8_t>& certificate_der_encoded) const {
        auto digest_algo_id = digest_algo_from_signature_algo(algo_id_);
        x509::digest_info di{x509::algorithm_id{digest_algo_id}, get_hash(digest_algo_id).input(certificate_der_encoded).result()};
        return std::make_pair(x509::algorithm_id{algo_id_}, x509::pkcs1_encode(private_key_, asn1::serialized(di)));
    }
private:
    asn1::object_id              algo_id_;
    const x509::rsa_private_key& private_key_;
};

rsa_certificate_signer::rsa_certificate_signer(const asn1::object_id& algorithm_id, const x509::rsa_private_key& private_key)
    : impl_(new impl{algorithm_id, private_key})
{
}

rsa_certificate_signer::~rsa_certificate_signer() = default;

certificate_signer::sign_result_t rsa_certificate_signer::do_sign(const std::vector<uint8_t>& certificate_der_encoded) const
{
    return impl_->sign(certificate_der_encoded);
}

} } // namespace funtls::x509
