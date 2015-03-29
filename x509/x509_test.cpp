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

void parse_Name(util::buffer_view& buf)
{

    // Name ::= CHOICE { RDNSequence }
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName 
    // RelativeDistinguishedName ::= SET OF AttributeValueAssertion
    // AttributeValueAssertion ::= SEQUENCE { AttributeType, AttributeValue }
    // AttributeType ::= OBJECT IDENTIFIER
    auto name_seq = asn1::sequence_view{asn1::read_der_encoded_value(buf)}; // RDNSequence
    while (name_seq.has_next()) {
        auto rdn_seq = asn1::set_view{name_seq.next()};
        while (rdn_seq.has_next()) {
            //auto av_pair_buf = asn1_expect_id(rdn_buf, asn1::identifier::constructed_sequence);
            auto av_pair = asn1::sequence_view{rdn_seq.next()};
            auto attribute_type = x509::attribute_type{av_pair.next()};
            const auto value = av_pair.next();
            const size_t name_max_length = 200;
            if (value.content_view().size() < 1 || value.content_view().size() > name_max_length) {
                throw std::runtime_error("Invalid length found in " + std::string(__PRETTY_FUNCTION__) + " id=" + std::to_string((uint8_t)value.id()) + " len=" + std::to_string(value.content_view().size()));
            }
            if (value.id() == asn1::identifier::printable_string || value.id() == asn1::identifier::utf8_string) {
                std::string s(value.content_view().size(), '\0');
                if (value.content_view().size()) value.content_view().read(&s[0], value.content_view().size());
                // TODO: check that the string is valid
                std::cout << " " << attribute_type << ": '" << s << "'" << std::endl;
            } else {
                // Only TeletexString, UniversalString or BMPString allowed here
                throw std::runtime_error("Unknown type found in " + std::string(__PRETTY_FUNCTION__) + " id=" + std::to_string((uint8_t)value.id()) + " len=" + std::to_string(value.content_view().size()));
            }
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

class asn1_bit_string {
public:
    asn1_bit_string(const std::vector<uint8_t>& data, size_t bit_count) : repr_(data), size_(bit_count) {
        if (bit_count == 0 || bit_count > data.size() * 8 || bit_count < data.size() * 8 - 7) {
            std::ostringstream oss;
            oss << "Invalid bit count " << bit_count << " for data size " << data.size();
            throw std::logic_error(oss.str());
        }
#ifndef NDEBUG
        const size_t remaining = data.size() * 8 - bit_count;
        assert(!remaining || (data[data.size()-1] & ((1<<remaining)-1)) == 0);
#endif
    }
    size_t size() const {
        return size_;
    }
    friend std::ostream& operator<<(std::ostream& os, const asn1_bit_string& bs) {
        os << util::base16_encode(&bs.repr_[0], bs.repr_.size());
        return os;
    }

    const uint8_t* data() const {
        return &repr_[0];
    }

private:
    std::vector<uint8_t> repr_;
    size_t               size_;
};

asn1_bit_string asn1_read_bit_string(util::buffer_view& parent_buf)
{
    auto data_buf = asn1_expect_id(parent_buf, asn1::identifier::bit_string);
    if (data_buf.remaining() < 2) {
        throw std::runtime_error("Too little data in bit string len="+std::to_string(data_buf.remaining()));
    }
    const uint8_t unused_bits = data_buf.get();
    if (unused_bits >= 8) {
        throw std::runtime_error("Invalid number of bits in bit string: "+std::to_string((int)unused_bits));
    }
    std::vector<uint8_t> data(data_buf.remaining());
    data_buf.read(&data[0], data.size());
    return {data, data.size()*8-unused_bits};
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
    auto bs_buf = pk_seq.next().complete_view();
    auto bs = asn1_read_bit_string(bs_buf);
    util::buffer_view pk_buf{bs.data(),bs.size()/8};
    const auto public_key = asn1_read_rsa_public_key(pk_buf);
    assert(!pk_seq.has_next());
    return public_key;
}

rsa_public_key parse_TBSCertificate(const asn1::der_encoded_value& repr)
{
    auto buf = repr.complete_view();
    auto elem_buf = asn1_expect_id(buf, asn1::identifier::constructed_sequence);

    auto version_buf = asn1_expect_id(elem_buf, asn1::identifier::context_specific_tag_0);
    auto version = asn1::integer{asn1::read_der_encoded_value(version_buf)}.as<uint8_t>();
    assert(version_buf.remaining() == 0);
    std::cout << "Version " << (version+1) << std::endl;
    assert(version == 2); // v3

    auto serial_number = asn1::integer{asn1::read_der_encoded_value(elem_buf)}.as<int_type>();
    std::cout << "Serial number: 0x" << std::hex << serial_number << std::dec << std::endl;

    auto algo_id = asn1_read_algorithm_identifer(asn1::read_der_encoded_value(elem_buf));
    const asn1::object_id sha256WithRSAEncryption{1,2,840,113549,1,1,11};
    std::cout << "Algorithm: " << algo_id;
    std::cout << "  - Expecting " << sha256WithRSAEncryption << " (sha256WithRSAEncryption)" << std::endl;
    assert(algo_id == sha256WithRSAEncryption);

    std::cout << "Issuer:\n";
    parse_Name(elem_buf);

    auto validity  = asn1::sequence_view(asn1::read_der_encoded_value(elem_buf));
    auto notbefore = asn1::utc_time{validity.next()};
    auto notafter  = asn1::utc_time{validity.next()};
    assert(!validity.has_next());
    std::cout << "Validity: Between " << notbefore << " and " << notafter << std::endl;

    std::cout << "Subject:\n";
    parse_Name(elem_buf);

    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //    algorithm            AlgorithmIdentifier,
    //    subjectPublicKey     BIT STRING  }
    auto subject_public_key = parse_RSAPublicKey(elem_buf);
    std::cout << std::hex;
    std::cout << "Subject public key: n=0x" << subject_public_key.modolus << " e=0x" << subject_public_key.public_exponent << std::endl;
    std::cout << std::dec;

    while (elem_buf.remaining()) {
        auto value = asn1::read_der_encoded_value(elem_buf);
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

int_type octets_to_int(const asn1_bit_string& bs)
{
    int_type res = 0;
    if (bs.size() % 8) {
        throw std::runtime_error(std::string("Invalid bit string size " + std::to_string(bs.size()) + " in " + __PRETTY_FUNCTION__));
    }
    for (unsigned i = 0; i < bs.size()/8; ++i) {
        res <<= 8;
        res |= (bs.data())[i];
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
    auto sig_value_buf = cert_seq.next().complete_view();
    auto sig_value = asn1_read_bit_string(sig_value_buf);
    std::cout << " " << sig_value.size() << " bits" << std::endl;
    std::cout << " " << sig_value << std::endl;
    assert(sig_value.size() % 8 == 0);
    assert(!cert_seq.has_next());

    // The signatureValue field contains a digital signature computed upon
    // the ASN.1 DER encoded tbsCertificate.  The ASN.1 DER encoded
    // tbsCertificate is used as the input to the signature function.

    // See 9.2 EMSA-PKCS1-v1_5 in RFC3447

    // The encrypted signature is stored as a base-256 encoded number in the bitstring
    const auto sig_int  = octets_to_int(sig_value);
    assert(sig_value.size()%8==0);
    const size_t em_len = sig_value.size()/8; // encrypted message length

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
