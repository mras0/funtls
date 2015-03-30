#include "x509.h"
#include <util/test.h>
#include <ostream>
#include <algorithm>

namespace {

funtls::x509::attribute_type::tag attribute_tag_from_oid(const funtls::asn1::object_id& oid)
{
    FUNTLS_CHECK_BINARY(oid.size(), ==, 4, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[0], ==, 2, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[1], ==, 5, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[2], ==, 4, "Invalid X509 attribute " + oid.as_string());
    return static_cast<funtls::x509::attribute_type::tag>(oid[3]);
}

funtls::x509::version::tag version_tag_from_int(const funtls::asn1::integer& i)
{
    FUNTLS_CHECK_BINARY(i.octet_count(), ==, 1, "Invalid X509 version");
    const auto ival = i.as<uint8_t>();
    switch (ival) {
        case 0: return funtls::x509::version::v1;
        case 1: return funtls::x509::version::v2;
        case 2: return funtls::x509::version::v3;
    }
    FUNTLS_CHECK_FAILURE("Unknown version int " + std::to_string(ival));
}

funtls::x509::version::tag read_tag(const funtls::asn1::der_encoded_value& repr)
{
    FUNTLS_CHECK_BINARY(repr.id(), ==, funtls::asn1::identifier::context_specific_tag_0, "Expected X509 version element");
    auto ver_content = repr.content_view();
    auto ver_int = funtls::asn1::integer{funtls::asn1::read_der_encoded_value(ver_content)};
    FUNTLS_CHECK_BINARY(ver_content.remaining(), ==, 0, "Extra content at end of X509 version element");
    return version_tag_from_int(ver_int);
}

funtls::x509::name::attr_type parse_name_attributes(const funtls::asn1::der_encoded_value& repr)
{
    using namespace funtls;
    // Name ::= CHOICE { RDNSequence }
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName 
    // RelativeDistinguishedName ::= SET OF AttributeValueAssertion
    // AttributeValueAssertion ::= SEQUENCE { AttributeType, AttributeValue }
    // AttributeType ::= OBJECT IDENTIFIER

    x509::name::attr_type res;
    auto name_seq = asn1::sequence_view{repr}; // RDNSequence
    while (name_seq.has_next()) {
        auto rdn_set = asn1::set_view{name_seq.next()};
        while (rdn_set.has_next()) {
            auto av_pair = asn1::sequence_view{rdn_set.next()};
            auto attribute_type = x509::attribute_type{av_pair.next()};
            const auto value = av_pair.next();
            std::string text;
            // TODO: preserve type information
            if (value.id() == asn1::identifier::printable_string) {
                text = asn1::printable_string{value}.as_string();
            } else if (value.id() == asn1::identifier::utf8_string) {
                text = asn1::utf8_string{value}.as_string();
            } else {
                // Only TeletexString, UniversalString or BMPString allowed here
                std::ostringstream oss;
                oss << "Unsupported attribute type " << attribute_type;
                FUNTLS_CHECK_FAILURE(oss.str());
            }
            auto find_attr = [&] (const x509::name::attr_type::value_type& a) { return a.first == attribute_type; };
            if (std::find_if(res.begin(), res.end(), find_attr) != res.end()) {
                std::ostringstream oss;
                oss << "Duplicate attribute type " << attribute_type;
                FUNTLS_CHECK_FAILURE(oss.str());
            }
            res.push_back(std::make_pair(attribute_type, text));
            if (av_pair.has_next()) {
                FUNTLS_CHECK_FAILURE("Excess data in X509 name attribute type/value pair");
            }
        }
        // end of RelativeDistinguishedName
    }
    return res;
}

funtls::x509::rsa_public_key asn1_read_rsa_public_key(const funtls::asn1::der_encoded_value& repr)
{
    auto elem_seq = funtls::asn1::sequence_view{repr};
    const auto modolus         = funtls::asn1::integer(elem_seq.next());
    const auto public_exponent = funtls::asn1::integer(elem_seq.next());
    assert(!elem_seq.has_next());
    return funtls::x509::rsa_public_key{modolus, public_exponent};
}

funtls::x509::rsa_public_key parse_RSAPublicKey(const funtls::asn1::der_encoded_value& repr)
{
    using namespace funtls; using namespace funtls::x509;
    auto pk_seq = asn1::sequence_view{repr};
    const auto pk_algo_id = x509::read_algorithm_identifer(pk_seq.next());
    if (pk_algo_id != rsaEncryption) {
        std::ostringstream oss;
        oss << "Unknown key algorithm id " << pk_algo_id << " expected rsaEncryption (" << rsaEncryption << ") in " << __PRETTY_FUNCTION__;
        throw std::runtime_error(oss.str());
    }
    // The public key is DER-encoded inside a bit string
    auto bs = asn1::bit_string{pk_seq.next()}.as_vector();
    util::buffer_view pk_buf{&bs[0], bs.size()};
    const auto public_key = asn1_read_rsa_public_key(asn1::read_der_encoded_value(pk_buf));
    assert(!pk_seq.has_next());
    return public_key;
}


} // unnamed namespace

namespace funtls { namespace x509 {

attribute_type::attribute_type(const asn1::der_encoded_value& repr)
    : tag_(attribute_tag_from_oid(asn1::object_id{repr}))
{
}

std::ostream& operator<<(std::ostream& os, const attribute_type& attr)
{
    switch (attr) {
    case attribute_type::common_name:
        os << "CN";
        break;
    case attribute_type::country_name:
        os << "C";
        break;
    case attribute_type::state_or_province_name:
        os << "ST";
        break;
    case attribute_type::organization_name:
        os << "O";
        break;
    default:
        os << "Unknown " << static_cast<uint32_t>(attr);
        break;
    }
    return os;
}

version::version(const asn1::der_encoded_value& repr)
    : tag_(read_tag(repr))
{
}

std::ostream& operator<<(std::ostream& os, const version& ver)
{
    switch (ver) {
        case version::v1:
            os << "x509_v1";
            break;
        case version::v2:
            os << "x509_v2";
            break;
        case version::v3:
            os << "x509_v3";
            break;
        default:
            assert(false);
            os << "Unknown version " << static_cast<unsigned>(ver);
    }

    return os;
}


name::name(const asn1::der_encoded_value& repr)
    : attributes_(parse_name_attributes(repr))
{
}

std::ostream& operator<<(std::ostream& os, const name& n)
{
    bool first = true;
    for (const auto a : n.attributes()) {
        if (first) {
            first = false;
        } else {
            os << ", ";
        }
        os << a.first << "=" << a.second;
    }
    return os;
}

v3_certificate parse_v3_cert(const asn1::der_encoded_value& repr)
{
    auto cert_seq = asn1::sequence_view{repr};

    auto ver = version{cert_seq.next()};
    FUNTLS_CHECK_BINARY(ver, ==, version::v3, "Only v3 X509 supported");

    auto serial_number = asn1::integer{cert_seq.next()};

    // signature algo
    auto algo_id = x509::read_algorithm_identifer(cert_seq.next());
    auto issuer = name{cert_seq.next()};

    auto validity  = asn1::sequence_view{cert_seq.next()};
    auto notbefore = asn1::utc_time{validity.next()};
    auto notafter  = asn1::utc_time{validity.next()};
    assert(!validity.has_next());

    auto subject = name{cert_seq.next()};

    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //    algorithm            AlgorithmIdentifier,
    //    subjectPublicKey     BIT STRING  }
    auto subject_public_key = parse_RSAPublicKey(cert_seq.next());
    while (cert_seq.has_next()) {
        auto value = cert_seq.next();
        if (value.id() == asn1::identifier::context_specific_tag_1) {
            assert(ver == 1 || ver == 2); // Must be v2 or v3
        } else if (value.id() == asn1::identifier::context_specific_tag_2) {
            assert(ver == 1 || ver == 2); // Must be v2 or v3
        } else if (value.id() == asn1::identifier::context_specific_tag_3) {
            assert(ver == 2); // Must be v3
        } else {
            std::ostringstream oss;
            oss << "Unknown tag found in " << __PRETTY_FUNCTION__ << ": " << value;
            throw std::runtime_error(oss.str());
        }
    }

    return v3_certificate{
        serial_number,
        algo_id,
        issuer,
        notbefore,
        notafter,
        subject,
        subject_public_key
    };
}

asn1::object_id read_algorithm_identifer(const asn1::der_encoded_value& value)
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


} } // namespace funtls::x509
