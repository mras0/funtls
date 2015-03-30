#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cassert>
#include <iomanip>
#include <array>

#include <util/base_conversion.h>
#include <util/buffer.h>
#include <asn1/asn1.h>

#include <x509/x509.h>

#include <util/test.h>
#include <hash/sha.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

util::buffer_view asn1_expect_id(util::buffer_view& buf, asn1::identifier expected_id)
{
    auto value = asn1::read_der_encoded_value(buf);
    if (value.id() != expected_id) {
        throw std::runtime_error(std::string(__PRETTY_FUNCTION__) + ": " + std::to_string(uint8_t(value.id())) + " is not expected id " + std::to_string(uint8_t(expected_id)));
    }

    return value.content_view();
}

void print_all(util::buffer_view& buf, const std::string& name)
{
    while (buf.remaining()) {
        auto value = asn1::read_der_encoded_value(buf);
        std::cout << name << " " << value << std::endl;
    }
}

void parse_Name(const asn1::der_encoded_value& repr)
{

    // Name ::= CHOICE { RDNSequence }
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName 
    // RelativeDistinguishedName ::= SET OF AttributeValueAssertion
    // AttributeValueAssertion ::= SEQUENCE { AttributeType, AttributeValue }
    // AttributeType ::= OBJECT IDENTIFIER
    auto name_seq = asn1::sequence_view{repr}; // RDNSequence
    while (name_seq.has_next()) {
        auto rdn_seq = asn1::set_view{name_seq.next()};
        while (rdn_seq.has_next()) {
            //auto av_pair_buf = asn1_expect_id(rdn_buf, asn1::identifier::constructed_sequence);
            auto av_pair = asn1::sequence_view{rdn_seq.next()};
            auto attribute_type = x509::attribute_type{av_pair.next()};
            const auto value = av_pair.next();
            std::string text;
            if (value.id() == asn1::identifier::printable_string) {
                text = asn1::printable_string{value}.as_string();
            } else if (value.id() == asn1::identifier::utf8_string) {
                text = asn1::utf8_string{value}.as_string();
            } else {
                // Only TeletexString, UniversalString or BMPString allowed here
                throw std::runtime_error("Unknown type found in " + std::string(__PRETTY_FUNCTION__) + " id=" + std::to_string((uint8_t)value.id()) + " len=" + std::to_string(value.content_view().size()));
            }
            std::cout << " " << attribute_type << ": '" << text << "'" << std::endl;
            assert(!av_pair.has_next());
        }
        // end of RelativeDistinguishedName
    }
}

asn1::object_id asn1_read_algorithm_identifer(const asn1::der_encoded_value& value)
{
    auto algo_seq = asn1::sequence_view{value};
    auto algo_id = asn1::object_id{algo_seq.next()}; // algorithm OBJECT IDENTIFIER,
    //parameters  ANY DEFINED BY algorithm OPTIONAL
    auto param_value = algo_seq.next();
    if (param_value.id() != asn1::identifier::null || param_value.content_view().size() != 0) { // parameters MUST be null for rsaEncryption at least
        std::ostringstream oss;
        oss << "Expected NULL parameter of length 0 in " << __PRETTY_FUNCTION__ << " got " << param_value;
        throw std::runtime_error(oss.str());
    }
    assert(!algo_seq.has_next());
    return algo_id;
}

struct rsa_public_key {
    int_type modolus;           // n
    int_type public_exponent;   // e
};

rsa_public_key asn1_read_rsa_public_key(util::buffer_view& parent_buf)
{
    auto elem_seq = asn1::sequence_view{asn1::read_der_encoded_value(parent_buf)};
    const auto modolus         = asn1::integer(elem_seq.next()).as<int_type>();
    const auto public_exponent = asn1::integer(elem_seq.next()).as<int_type>();
    assert(!elem_seq.has_next());
    return rsa_public_key{modolus, public_exponent};
}

static const asn1::object_id x509_rsaEncryption{ 1,2,840,113549,1,1,1 };
static const asn1::object_id x509_sha256WithRSAEncryption{ 1,2,840,113549,1,1,11 };

// https://tools.ietf.org/html/rfc4055
rsa_public_key parse_RSAPublicKey(util::buffer_view& buf)
{
    auto pk_seq = asn1::sequence_view{asn1::read_der_encoded_value(buf)};
    const auto pk_algo_id = asn1_read_algorithm_identifer(pk_seq.next());
    if (pk_algo_id != x509_rsaEncryption) {
        std::ostringstream oss;
        oss << "Unknown key algorithm id " << pk_algo_id << " expected rsaEncryption (" << x509_rsaEncryption << ") in " << __PRETTY_FUNCTION__;
        throw std::runtime_error(oss.str());
    }
    // The public key is DER-encoded inside a bit string
    auto bs = asn1::bit_string{pk_seq.next()}.as_vector();
    util::buffer_view pk_buf{&bs[0], bs.size()};
    const auto public_key = asn1_read_rsa_public_key(pk_buf);
    assert(!pk_seq.has_next());
    return public_key;
}

rsa_public_key parse_TBSCertificate(const asn1::der_encoded_value& repr)
{
    auto cert_seq = asn1::sequence_view{repr};

    auto version = x509::version{cert_seq.next()};
    std::cout << "Version " << version << std::endl;
    assert(version == x509::version::v3);

    auto serial_number = asn1::integer{cert_seq.next()}.as<int_type>();
    std::cout << "Serial number: 0x" << std::hex << serial_number << std::dec << std::endl;

    auto algo_id = asn1_read_algorithm_identifer(cert_seq.next());
    const asn1::object_id sha256WithRSAEncryption{1,2,840,113549,1,1,11};
    std::cout << "Algorithm: " << algo_id;
    std::cout << "  - Expecting " << sha256WithRSAEncryption << " (sha256WithRSAEncryption)" << std::endl;
    assert(algo_id == sha256WithRSAEncryption);

    std::cout << "Issuer:\n";
    parse_Name(cert_seq.next());

    auto validity  = asn1::sequence_view{cert_seq.next()};
    auto notbefore = asn1::utc_time{validity.next()};
    auto notafter  = asn1::utc_time{validity.next()};
    assert(!validity.has_next());
    std::cout << "Validity: Between " << notbefore << " and " << notafter << std::endl;

    std::cout << "Subject:\n";
    parse_Name(cert_seq.next());

    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //    algorithm            AlgorithmIdentifier,
    //    subjectPublicKey     BIT STRING  }
    auto s_pk_buf = cert_seq.next().complete_view();
    auto subject_public_key = parse_RSAPublicKey(s_pk_buf);
    std::cout << std::hex;
    std::cout << "Subject public key: n=0x" << subject_public_key.modolus << " e=0x" << subject_public_key.public_exponent << std::endl;
    std::cout << std::dec;

    while (cert_seq.has_next()) {
        auto value = cert_seq.next();
        if (value.id() == asn1::identifier::context_specific_tag_1) {
            assert(version == 1 || version == 2); // Must be v2 or v3
        } else if (value.id() == asn1::identifier::context_specific_tag_2) {
            assert(version == 1 || version == 2); // Must be v2 or v3
        } else if (value.id() == asn1::identifier::context_specific_tag_3) {
            assert(version == 2); // Must be v3
        } else {
            std::ostringstream oss;
            oss << "Unknown tag found in " << __PRETTY_FUNCTION__ << ": " << value;
            throw std::runtime_error(oss.str());
        }
    }

    return subject_public_key;
}

std::array<uint8_t, SHA256HashSize> sha256(const void* data, size_t len)
{
    SHA256Context context;
    SHA256Reset(&context);
    SHA256Input(&context, static_cast<const uint8_t*>(data), len);
    std::array<uint8_t, SHA256HashSize> digest;
    SHA256Result(&context, &digest[0]);
    return digest;
}

int_type octets_to_int(const std::vector<uint8_t>& bs)
{
    int_type res = 0;
    for (const auto& elem : bs) {
        res <<= 8;
        res |= elem;
    }
    return res;
}

std::vector<uint8_t> int_to_octets(int_type i, size_t byte_count)
{
    std::vector<uint8_t> result(byte_count);
    while (byte_count--) {
        result[byte_count] = static_cast<uint8_t>(i);
        i >>= 8;
    }
    if (i) {
        throw std::logic_error("Number too large in " + std::string(__PRETTY_FUNCTION__));
    }
    return result;
}

std::vector<uint8_t> buffer_copy(const util::buffer_view& buf)
{
    auto mut_buf = buf;
    std::vector<uint8_t> data(mut_buf.remaining());
    if (!data.empty()) mut_buf.read(&data[0], data.size());
    return data;
}

void parse_x509_v3(util::buffer_view& buf) // in ASN.1 DER encoding (X.690)
{
    auto cert_seq = asn1::sequence_view{asn1::read_der_encoded_value(buf)};
    auto tbs_cert = cert_seq.next();
    // Save certificate data for verification against the signature
    const auto tbsCertificate = buffer_copy(tbs_cert.complete_view());

    auto subject_public_key = parse_TBSCertificate(tbs_cert);

    auto sig_algo = asn1_read_algorithm_identifer(cert_seq.next());
    std::cout << "Signature algorithm: " << sig_algo << std::endl;
    assert(sig_algo == x509_sha256WithRSAEncryption);
    auto sig_value = asn1::bit_string{cert_seq.next()}.as_vector();
    std::cout << " " << sig_value.size() << " bits" << std::endl;
    std::cout << " " << util::base16_encode(sig_value) << std::endl;
    assert(!cert_seq.has_next());

    // The signatureValue field contains a digital signature computed upon
    // the ASN.1 DER encoded tbsCertificate.  The ASN.1 DER encoded
    // tbsCertificate is used as the input to the signature function.

    // See 9.2 EMSA-PKCS1-v1_5 in RFC3447

    // The encrypted signature is stored as a base-256 encoded number in the bitstring
    const auto sig_int  = octets_to_int(sig_value);
    const size_t em_len = sig_value.size(); // encrypted message length

    // Decode the signature using the issuers public key (here using the subjects PK since the cert is selfsigned)
    const auto issuer_pk = subject_public_key;
    const auto decoded = int_to_octets(powm(sig_int, issuer_pk.public_exponent, issuer_pk.modolus), em_len);
    std::cout << "Decoded signature:\n" << util::base16_encode(&decoded[0], decoded.size()) << std::endl;

    // EM = 0x00 || 0x01 || PS || 0x00 || T (T=DER encoded DigestInfo)
    auto digest_buf = util::buffer_view{&decoded[0], decoded.size()};
    const auto sig0 = digest_buf.get();
    const auto sig1 = digest_buf.get();
    if (sig0 != 0x00 || sig1 != 0x01) {
        throw std::runtime_error("Invalid PKCS#1 1.5 signature. Expected 0x00 0x01 Got: 0x" + util::base16_encode(&sig0, 1) + " 0x" + util::base16_encode(&sig1, 1));
    }
    // Skip padding
    for (;;) {
        const auto b = digest_buf.get();
        if (b == 0xff) { // Padding...
            continue;
        } else if (b == 0x00) { // End of padding
            break;
        } else {
            throw std::runtime_error("Invalid byte in PKCS#1 1.5 padding: 0x" + util::base16_encode(&b, 1));
        }
    }
    // DigestInfo ::= SEQUENCE {
    //   digestAlgorithm AlgorithmIdentifier,
    //   digest OCTET STRING }

    auto digest_info = asn1::sequence_view{asn1::read_der_encoded_value(digest_buf)};
    assert(digest_buf.remaining() == 0);

    auto digest_algo = asn1_read_algorithm_identifer(digest_info.next());
    std::cout << "Digest algorithm: " << digest_algo << std::endl;
    static const asn1::object_id id_sha256{2,16,840,1,101,3,4,2,1};
    assert(digest_algo == id_sha256);
    auto digest = asn1::octet_string{digest_info.next()}.as_vector();
    assert(!digest_info.has_next());

    if (digest.size() != SHA256HashSize) {
        throw std::runtime_error("Invalid digest size expected " + std::to_string(SHA256HashSize) + " got " + std::to_string(digest.size()) + " in " + __PRETTY_FUNCTION__);
    }

    std::cout << "Digest: " << util::base16_encode(&digest[0], digest.size()) << std::endl;

    // The below is very ugly, but basically we need to check
    // all of the DER encoded data in tbsCertificate (including the id and length octets)
    util::buffer_view temp_buf(&tbsCertificate[0], tbsCertificate.size());
    auto cert_value = asn1::read_der_encoded_value(temp_buf);
    assert(cert_value.id() == asn1::identifier::constructed_sequence);

    const auto calced_digest = sha256(&tbsCertificate[0], cert_value.complete_view().size());
    std::cout << "Calculated digest: " << util::base16_encode(&calced_digest[0], calced_digest.size()) << std::endl;
    if (!std::equal(calced_digest.begin(), calced_digest.end(), digest.begin())) {
        throw std::runtime_error("Digest mismatch in " + std::string(__PRETTY_FUNCTION__) + " Calculated: " +
                util::base16_encode(&calced_digest[0], calced_digest.size()) + " Expected: " +
                util::base16_encode(&digest[0], digest.size()));
    }
}

std::vector<uint8_t> read_file(const std::string& filename)
{
    std::ifstream in(filename);
    if (!in || !in.is_open()) {
        throw std::runtime_error("Could not open " + filename);
    }
    in.seekg(0, std::ifstream::end);
    std::vector<uint8_t> buffer(in.tellg());
    in.seekg(0, std::ifstream::beg);
    in.read(reinterpret_cast<char*>(&buffer[0]), buffer.size());
    if (!in) {
        throw std::runtime_error("Error reading from " + filename);
    }
    return buffer;
}

int main()
{
    auto cert = read_file("server.crt");
    assert(cert.size());
    util::buffer_view cert_buf(&cert[0], cert.size());
    parse_x509_v3(cert_buf);
}
