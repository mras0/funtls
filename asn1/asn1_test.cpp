#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cassert>
#include <iomanip>
#include <array>

#include <hash/sha.h>
#include <util/base_conversion.h>
#include <util/buffer.h>
#include <util/test.h>
#include <asn1/asn1.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

asn1::identifier read_asn1_identifier(util::buffer_view& buf)
{
    uint8_t id = buf.get();
    // If the identifier is not universal, its tag may be a number that is greater than 30. 
    // In that case, the tag does not fit in the 5-bit tag field, and must be encoded in subsequent octets. 
    // The value 11111 is reserved for identifying such encodings.
    assert((id&0x1f)!=31);
    return asn1::identifier{static_cast<asn1::identifier::tag>(id)};
}

size_t read_asn1_length(util::buffer_view& buf)
{
    const uint8_t first_size_byte = buf.get();
    if (first_size_byte & 0x80) {
        const uint8_t length_octets = first_size_byte & 0x7f;
        if (length_octets == 0x7f) throw std::runtime_error("Illegal length octet");
        if (length_octets > sizeof(size_t)) throw std::runtime_error("Unsupported length octet count " + std::to_string(length_octets));
        size_t sz = 0;
        for (unsigned i = 0; i < length_octets; ++i) {
            sz <<= 8;
            sz |= buf.get();
        }
        return sz;
    } else {
        return first_size_byte & 0x7f;
    }
}

util::buffer_view asn1_expect_id(util::buffer_view& buf, asn1::identifier expected_id)
{
    const auto id = read_asn1_identifier(buf);
    if (id != expected_id) {
        throw std::runtime_error(std::string(__PRETTY_FUNCTION__) + ": " + std::to_string(uint8_t(id)) + " is not expected id " + std::to_string(uint8_t(expected_id)));
    }

    const auto len = read_asn1_length(buf);
    return buf.get_slice(len);
}

int_type asn1_read_integer(util::buffer_view& buf)
{
    auto int_buf = asn1_expect_id(buf, asn1::identifier::integer);
    if (int_buf.size() < 1 || int_buf.size() > 1000) {
        throw std::runtime_error("Invalid integer size " + std::to_string(int_buf.size()) + " in " + __PRETTY_FUNCTION__);
    }
    int_type val = static_cast<int8_t>(int_buf.get()); // assumes native 2's complement notation
    for (size_t i = 1; i < int_buf.size(); ++i) {
        val <<= 8;
        val |= int_buf.get();
    }
    return val;
}

std::vector<uint8_t> asn1_read_octet_string(util::buffer_view& buf)
{
    auto os_buf = asn1_expect_id(buf, asn1::identifier::octet_string);
    std::vector<uint8_t> os(os_buf.remaining());
    if (!os.empty()) os_buf.read(&os[0], os.size());
    return os;
}

bool asn1_is_valid_printable_character(char c)
{
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= '0' && c <= '9') return true;
    for (const char* check_char = " '()+,-./:=?"; *check_char; ++check_char) {
        if (*check_char == c) return true;
    }
    return false;
}

asn1::object_id asn1_read_object_id(util::buffer_view& buf)
{
    auto oid_buf = asn1_expect_id(buf, asn1::identifier::object_id);
    if (oid_buf.size() < 1 || oid_buf.size() > 20) { // What are common sizes?
        throw std::runtime_error("Invalid oid size " + std::to_string(oid_buf.size()) + " in " + __PRETTY_FUNCTION__);
    }
    const uint8_t first = oid_buf.get();
    std::vector<uint32_t> res;
    /*
       The first octet has value 40 * value1 + value2.
       (This is unambiguous, since value1 is limited to values 0, 1, and 2; value2 is limited to the 
       range 0 to 39 when value1 is 0 or 1; and, according to X.208, n is always at least 2.)
    */
    res.push_back(first/40);
    res.push_back(first%40);

    /*
       The following octets, if any, encode value3, ..., valuen. Each value is encoded base 128, 
       most significant digit first, with as few digits as possible, and the most significant bit 
       of each octet except the last in the value's encoding set to "1."*
       }
    */
    while (oid_buf.remaining()) {
        uint32_t value = 0;
        uint8_t read_byte = 0;
        do {
            if (value >= (1<<21)) {
                // OIDs must be less than 2^28, so if the value before shifting by 7 is >= 2^21
                // it is about to become out of range
                throw std::runtime_error("OID value out of range in " + std::string(__PRETTY_FUNCTION__));
            }
            read_byte = oid_buf.get();
            value <<= 7;
            value |= read_byte & 0x7f;
        } while (read_byte & 0x80);
        res.push_back(value);
    }

    assert(oid_buf.remaining() == 0);
    return res;
}

void print_all(util::buffer_view& buf, const char* name)
{
    while (buf.remaining()) {
        // identifer, length, content, end-of-content

        auto id = read_asn1_identifier(buf);
        auto len = read_asn1_length(buf);

        std::cout << name << " len=" << std::setw(4) << len << " " << id << std::endl;
        buf.skip(len);
    }
}
enum class x500_attribute_type : uint32_t {
    objectClass = 0,
    aliasedEntryName = 1,
    knowldgeinformation = 2,
    commonName = 3,
    surname = 4,
    serialNumber = 5,
    countryName = 6,
    localityName = 7,
    stateOrProvinceName = 8,
    streetAddress = 9,
    organizationName = 10,
    organizationalUnitName = 11,
    title = 12,
    description = 13,
    searchGuide = 14,
    businessCategory = 15,
    postalAddress = 16,
    postalCode = 17,
    postOfficeBox = 18,
    physicalDeliveryOfficeName = 19,
    telephoneNumber = 20,
    telexNumber = 21,
    teletexTerminalIdentifier = 22,
    facsimileTelephoneNumber = 23,
    x121Address = 24,
    internationalISDNNumber = 25,
    registeredAddress = 26,
    destinationIndicator = 27,
    preferredDeliveryMethod = 28,
    presentationAddress = 29,
    supportedApplicationContext = 30,
    member = 31,
    owner = 32,
    roleOccupant = 33,
    seeAlso = 34,
    userPassword = 35,
    userCertificate = 36,
    cACertificate = 37,
    authorityRevocationList = 38,
    certificateRevocationList = 39,
    crossCertificatePair = 40,
    name = 41,
    givenName = 42,
    initials = 43,
    generationQualifier = 44,
    uniqueIdentifier = 45,
    dnQualifier = 46,
    enhancedSearchGuide = 47,
    protocolInformation = 48,
    distinguishedName = 49,
    uniqueMember = 50,
    houseIdentifier = 51,
    supportedAlgorithms = 52,
    deltaRevocationList = 53,
    //    Attribute Certificate attribute (attributeCertificate) = 58
    pseudonym = 65,
};

std::ostream& operator<<(std::ostream& os, const x500_attribute_type& attr) {
    switch (attr) {

    case x500_attribute_type::commonName:
        os << "Common name";
        break;
    case x500_attribute_type::countryName:
        os << "Country";
        break;
    case x500_attribute_type::stateOrProvinceName:
        os << "State/Province";
        break;
    case x500_attribute_type::organizationName:
        os << "Organization";
        break;
    default:
        os << "Unknown " << static_cast<uint32_t>(attr);
        break;
    }
    return os;
}

void parse_Name(util::buffer_view& buf)
{

    // Name ::= CHOICE { RDNSequence }
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName 
    // RelativeDistinguishedName ::= SET OF AttributeValueAssertion
    // AttributeValueAssertion ::= SEQUENCE { AttributeType, AttributeValue }
    // AttributeType ::= OBJECT IDENTIFIER
    auto name_buf = asn1_expect_id(buf, asn1::identifier::constructed_sequence); // RDNSequence
    while (name_buf.remaining()) {
        auto rdn_buf = asn1_expect_id(name_buf, asn1::identifier::constructed_set);
        while (rdn_buf.remaining()) {
            auto av_pair_buf = asn1_expect_id(rdn_buf, asn1::identifier::constructed_sequence);
            auto attribute_type = asn1_read_object_id(av_pair_buf);

            // 2.5.4 - X.500 attribute types
            // http://www.alvestrand.no/objectid/2.5.4.html
            if (attribute_type.size() != 4 || attribute_type[0] != 2 || attribute_type[1] != 5 || attribute_type[2] != 4) {
                std::ostringstream oss;
                oss << "Invalid attribute found in " << __PRETTY_FUNCTION__ << ": " << attribute_type;
                throw std::runtime_error(oss.str());
            }
            const auto x500_attr_type = static_cast<x500_attribute_type>(attribute_type[3]);
            auto id = read_asn1_identifier(av_pair_buf);
            auto len = read_asn1_length(av_pair_buf);
            const size_t name_max_length = 200;
            if (len < 1 || len > name_max_length) {
                throw std::runtime_error("Invalid length found in " + std::string(__PRETTY_FUNCTION__) + " id=" + std::to_string((uint8_t)id) + " len=" + std::to_string(len));
            }
            if (id == asn1::identifier::printable_string || id == asn1::identifier::utf8_string) {
                std::string s(len, '\0');
                if (len) av_pair_buf.read(&s[0], len);
                // TODO: check that the string is valid
                std::cout << " " << x500_attr_type << ": '" << s << "'" << std::endl;
            } else {
                // Only TeletexString, UniversalString or BMPString allowed here
                throw std::runtime_error("Unknown type found in " + std::string(__PRETTY_FUNCTION__) + " id=" + std::to_string((uint8_t)id) + " len=" + std::to_string(len));
            }
            assert(av_pair_buf.remaining() == 0);
        }
        // end of RelativeDistinguishedName
    }
}

asn1::utc_time parse_UTCTime(util::buffer_view& parent_buf)
{
    auto time_buf = asn1_expect_id(parent_buf, asn1::identifier::utc_time);
    std::string s(time_buf.remaining(), '\0');
    if (!s.empty()) time_buf.read(&s[0], s.length());
    return s;
}

asn1::object_id asn1_read_algorithm_identifer(util::buffer_view& parent_buf)
{
    auto algo_buf = asn1_expect_id(parent_buf, asn1::identifier::constructed_sequence);
    auto algo_id = asn1_read_object_id(algo_buf); // algorithm OBJECT IDENTIFIER,
    //parameters  ANY DEFINED BY algorithm OPTIONA
    auto param_id = read_asn1_identifier(algo_buf);
    auto param_len = read_asn1_length(algo_buf);
    if (param_id != asn1::identifier::null || param_len != 0) { // parameters MUST be null for rsaEncryption at least
        std::ostringstream oss;
        oss << "Expected NULL parameter of length 0 in " << __PRETTY_FUNCTION__ << " got " << param_id << " of length " << param_len;
        throw std::runtime_error(oss.str());
    }
    assert(algo_buf.remaining() == 0);
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
    auto elem_buf = asn1_expect_id(parent_buf, asn1::identifier::constructed_sequence);
    const auto modolus         = asn1_read_integer(elem_buf);
    const auto public_exponent = asn1_read_integer(elem_buf);
    assert(elem_buf.remaining() == 0);
    return rsa_public_key{modolus, public_exponent};
}

class algorithm_info {
public:
    algorithm_info(const std::string& name, const asn1::object_id& algorithm_identifier)
        : name_(name)
        , algorithm_identifier_(algorithm_identifier) {
    }

    std::string    name() const { return name_; }
    asn1::object_id algorithm_identifier() const { return algorithm_identifier_; }

private:
    std::string     name_;
    asn1::object_id  algorithm_identifier_;
};

static const asn1::object_id x509_rsaEncryption{ 1,2,840,113549,1,1,1 };
static const asn1::object_id x509_sha256WithRSAEncryption{ 1,2,840,113549,1,1,11 };

static const algorithm_info x509_algorithms[] = {
    // 1.2.840.113549.1.1 - PKCS-1
    { "rsaEncryption"           , x509_rsaEncryption },
    { "sha256WithRSAEncryption" , x509_sha256WithRSAEncryption  },
};

const algorithm_info& info_from_algorithm_id(const asn1::object_id& oid)
{
    for (const auto& algo : x509_algorithms) {
        if (algo.algorithm_identifier() == oid) {
            return algo;
        }
    }
    std::ostringstream oss;
    oss << "Unknown algorithm identifier " << oid;
    throw std::runtime_error(oss.str());
}

std::ostream& operator<<(std::ostream& os, const algorithm_info& ai)
{
    os << ai.name() << " (" << ai.algorithm_identifier() << ")";
    return os;
}

// https://tools.ietf.org/html/rfc4055
rsa_public_key parse_RSAPublicKey(util::buffer_view& buf)
{
    auto public_key_buf = asn1_expect_id(buf, asn1::identifier::constructed_sequence);
    const auto pk_algo_id = asn1_read_algorithm_identifer(public_key_buf);
    if (pk_algo_id != x509_rsaEncryption) {
        std::ostringstream oss;
        oss << "Unknown key algorithm id " << pk_algo_id << " expected rsaEncryption (" << x509_rsaEncryption << ") in " << __PRETTY_FUNCTION__;
        throw std::runtime_error(oss.str());
    }
    // The public key is DER-encoded inside a bit string
    auto bs = asn1_read_bit_string(public_key_buf);
    util::buffer_view pk_buf{bs.data(),bs.size()/8};
    const auto public_key = asn1_read_rsa_public_key(pk_buf);
    assert(public_key_buf.remaining() == 0);
    return public_key;
}

rsa_public_key parse_TBSCertificate(util::buffer_view& elem_buf)
{
    auto version_buf = asn1_expect_id(elem_buf, asn1::identifier::context_specific_tag_0);
    auto version = asn1_read_integer(version_buf);
    assert(version_buf.remaining() == 0);
    std::cout << "Version " << (version+1) << std::endl;
    assert(version == 2); // v3

    auto serial_number = asn1_read_integer(elem_buf);
    std::cout << "Serial number: 0x" << std::hex << serial_number << std::dec << std::endl;

    auto algo_id = asn1_read_algorithm_identifer(elem_buf);
    const asn1::object_id sha256WithRSAEncryption{1,2,840,113549,1,1,11};
    std::cout << "Algorithm: " << algo_id;
    std::cout << "  - Expecting " << sha256WithRSAEncryption << " (sha256WithRSAEncryption)" << std::endl;
    assert(algo_id == sha256WithRSAEncryption);

    std::cout << "Issuer:\n";
    parse_Name(elem_buf);

    auto validity_buf = asn1_expect_id(elem_buf, asn1::identifier::constructed_sequence);
    auto notbefore    = parse_UTCTime(validity_buf);
    auto notafter     = parse_UTCTime(validity_buf);
    assert(validity_buf.remaining() == 0);
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
        auto id = read_asn1_identifier(elem_buf);
        auto len = read_asn1_length(elem_buf);
        if (id == asn1::identifier::context_specific_tag_1) {
            assert(version == 1 || version == 2); // Must be v2 or v3
            elem_buf.skip(len); // Skip issuerUniqueID
        } else if (id == asn1::identifier::context_specific_tag_2) {
            assert(version == 1 || version == 2); // Must be v2 or v3
            elem_buf.skip(len); // Skip subjectUniqueID
        } else if (id == asn1::identifier::context_specific_tag_3) {
            assert(version == 2); // Must be v3
            elem_buf.skip(len); // Skip extensions
        } else {
            std::ostringstream oss;
            oss << "Unknown tag found in " << __PRETTY_FUNCTION__ << ": " << id << " len = " << len;
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
    auto elem_buf = asn1_expect_id(buf, asn1::identifier::constructed_sequence);
    // Save certificate data for verification against the signature
    const auto tbsCertificate = buffer_copy(elem_buf);

    auto cert_buf = asn1_expect_id(elem_buf, asn1::identifier::constructed_sequence);
    if (!cert_buf.remaining()) {
        throw std::runtime_error("Empty certificate in " + std::string(__PRETTY_FUNCTION__));
    }

    auto subject_public_key = parse_TBSCertificate(cert_buf);

    auto sig_algo = info_from_algorithm_id(asn1_read_algorithm_identifer(elem_buf));
    std::cout << "Signature algorithm: " << sig_algo << std::endl;
    assert(sig_algo.algorithm_identifier() == x509_sha256WithRSAEncryption);
    auto sig_value = asn1_read_bit_string(elem_buf);
    std::cout << " " << sig_value.size() << " bits" << std::endl;
    std::cout << " " << sig_value << std::endl;
    assert(sig_value.size() % 8 == 0);
    assert(elem_buf.remaining() == 0);

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

    auto digest_info_buf = asn1_expect_id(digest_buf, asn1::identifier::constructed_sequence);
    assert(digest_buf.remaining() == 0);

    auto digest_algo = asn1_read_algorithm_identifer(digest_info_buf);
    std::cout << "Digest algorithm: " << digest_algo << std::endl;
    static const asn1::object_id id_sha256{2,16,840,1,101,3,4,2,1};
    assert(digest_algo == id_sha256);
    auto digest = asn1_read_octet_string(digest_info_buf);
    assert(digest_info_buf.remaining() == 0);

    if (digest.size() != SHA256HashSize) {
        throw std::runtime_error("Invalid digest size expected " + std::to_string(SHA256HashSize) + " got " + std::to_string(digest.size()) + " in " + __PRETTY_FUNCTION__);
    }

    std::cout << "Digest: " << util::base16_encode(&digest[0], digest.size()) << std::endl;

    // The below is very ugly, but basically we need to check
    // all of the DER encoded data in tbsCertificate (including the id and length octets)
    util::buffer_view temp_buf(&tbsCertificate[0], tbsCertificate.size());
    auto cert_id = read_asn1_identifier(temp_buf);
    auto cert_len = read_asn1_length(temp_buf);
    cert_len += tbsCertificate.size() - temp_buf.remaining();
    assert(cert_id == asn1::identifier::constructed_sequence);
    assert(cert_len < tbsCertificate.size());

    const auto calced_digest = sha256(&tbsCertificate[0], cert_len);
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

funtls::asn1::der_encoded_value value_from_bytes(const std::vector<uint8_t>& data)
{
    assert(data.size());
    funtls::util::buffer_view buf(&data[0], data.size());
    auto value = funtls::asn1::read_der_encoded_value(buf);
    FUNTLS_ASSERT_EQUAL(0, buf.remaining());
    return value;
}

void test_der_encoded_value()
{
    using namespace funtls::util;
    using namespace funtls::asn1;

    const auto null_value_bytes = std::vector<uint8_t>{static_cast<uint8_t>(identifier::null), 0};
    auto null_value = value_from_bytes(null_value_bytes);
    FUNTLS_ASSERT_EQUAL(identifier::null, null_value.id());
    FUNTLS_ASSERT_EQUAL(0, null_value.length());
    FUNTLS_ASSERT_EQUAL(0, null_value.content_view().size());

    const auto int_value_1_bytes = std::vector<uint8_t>{static_cast<uint8_t>(identifier::integer), 1, 42};
    auto int_value_1 = value_from_bytes(int_value_1_bytes);
    FUNTLS_ASSERT_EQUAL(identifier::integer, int_value_1.id());
    FUNTLS_ASSERT_EQUAL(1, int_value_1.length());
    FUNTLS_ASSERT_EQUAL(1, int_value_1.content_view().size());
    FUNTLS_ASSERT_EQUAL(42, int_value_1.content_view().get());
}

int main()
{
    test_der_encoded_value();

    auto cert = read_file("server.crt");
    assert(cert.size());
    util::buffer_view cert_buf(&cert[0], cert.size());
    parse_x509_v3(cert_buf);
}
