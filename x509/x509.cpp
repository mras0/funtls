#include "x509.h"
#include <util/test.h>
#include <util/base_conversion.h>
#include <ostream>
#include <algorithm>

using namespace funtls;

namespace {

constexpr auto x509_version_tag = funtls::asn1::identifier::context_specific_tag_0;

x509::attribute_type::tag attribute_tag_from_oid(const asn1::object_id& oid)
{
    // XXX: HACK: See header.
    static const auto pkcs9_emailAddress = asn1::object_id{1,2,840,113549,1,9,1};
    if (oid == pkcs9_emailAddress) {
        return x509::attribute_type::tag::email_address;
    }
    FUNTLS_CHECK_BINARY(oid.size(), ==, 4, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[0], ==, 2, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[1], ==, 5, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[2], ==, 4, "Invalid X509 attribute " + oid.as_string());
    return static_cast<x509::attribute_type::tag>(oid[3]);
}

enum x509::version::tag version_tag_from_int(const asn1::integer& i)
{
    FUNTLS_CHECK_BINARY(i.octet_count(), ==, 1, "Invalid X509 version");
    const auto ival = i.as<uint8_t>();
    switch (ival) {
        case 0: return x509::version::v1;
        case 1: return x509::version::v2;
        case 2: return x509::version::v3;
    }
    FUNTLS_CHECK_FAILURE("Unknown version int " + std::to_string(ival));
}

enum x509::version::tag read_version_tag(const asn1::der_encoded_value& repr)
{
    FUNTLS_CHECK_BINARY(repr.id(), ==, x509_version_tag, "Expected X509 version element");
    auto ver_content = repr.content_view();
    auto ver_int = asn1::integer{asn1::read_der_encoded_value(ver_content)};
    FUNTLS_CHECK_BINARY(ver_content.remaining(), ==, 0, "Extra content at end of X509 version element");
    return version_tag_from_int(ver_int);
}

x509::name::attr_type parse_name_attributes(const asn1::der_encoded_value& repr)
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
            } else if (value.id() == asn1::identifier::t61_string) {
                text = asn1::t61_string{value}.as_string();
            } else if (value.id() == asn1::identifier::ia5_string) {
                text = asn1::ia5_string{value}.as_string();
            } else {
                // Only TeletexString, UniversalString or BMPString allowed here
                std::ostringstream oss;
                oss << "Unsupported value type " << value.id() << " for attribute type " << attribute_type;
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

std::vector<uint8_t> buffer_copy(const util::buffer_view& buf)
{
    auto mut_buf = buf;
    std::vector<uint8_t> data(mut_buf.remaining());
    if (!data.empty()) mut_buf.read(&data[0], data.size());
    return data;
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
    case attribute_type::common_name:              return os << "CN";
    case attribute_type::country_name:             return os << "C";
    case attribute_type::locality_name:            return os << "L";
    case attribute_type::state_or_province_name:   return os << "ST";
    case attribute_type::organization_name:        return os << "O";
    case attribute_type::organizational_unit_name: return os << "OU";
    case attribute_type::email_address:            return os << "E";
    }
    return os << "Unknown " << static_cast<uint32_t>(attr);
    return os;
}

std::ostream& operator<<(std::ostream& os, const version& ver)
{
    switch (ver.tag()) {
    case version::v1: return os << "x509_v1";
    case version::v2: return os << "x509_v2";
    case version::v3: return os << "x509_v3";
    }
    assert(false);
    return os << "Unknown version " << static_cast<unsigned>(ver.tag());
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

algorithm_id::algorithm_id(const asn1::der_encoded_value& repr)
    : id_({0,0,0})
{
    auto algo_seq = asn1::sequence_view{repr};
    id_ = asn1::object_id{algo_seq.next()}; // algorithm OBJECT IDENTIFIER,
    if (!algo_seq.has_next()) {
        return;
    }
    //parameters  ANY DEFINED BY algorithm OPTIONAL
    parameters_ = buffer_copy(algo_seq.next().complete_view());
    FUNTLS_CHECK_BINARY(algo_seq.has_next(), ==, false, "Unexpected element after optional parameters");
}

bool algorithm_id::null_parameters() const {
    if (parameters_.empty()) return true;
    if (parameters_.size() == 2 && parameters_[0] == asn1::identifier::tag::null && parameters_[1] == 0) {
        return true;
    }
    return false;
}

std::ostream& operator<<(std::ostream& os, const algorithm_id& aid)
{
    os << aid.id();
    if (!aid.null_parameters()) {
        os << "[parameters: " << util::base16_encode(aid.parameters()) << "]";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const x509::certificate& cert)
{
    auto c = cert.tbs();
    os << "Certificate " << c.version << " :" << std::endl;
    os << " Serial number: 0x" << util::base16_encode(c.serial_number.as_vector()) << std::endl;
    os << " Signature algorithm: " << c.signature_algorithm <<  std::endl;
    os << " Issuer: " << c.issuer << std::endl;
    os << " Validity: Between " << c.validity_not_before << " and " << c.validity_not_after << std::endl;
    os << " Subject: " << c.subject << std::endl;
    os << " Subject public key algorithm: " << c.subject_public_key_algo << std::endl;
    os << "Signature algorithm: " << cert.signature_algorithm() << std::endl;
    return os;
}


tbs_certificate parse_tbs_certificate(const asn1::der_encoded_value& repr)
{
    auto cert_seq = asn1::sequence_view{repr};

    version ver{}; // default v1

    // The first elemnt could be a version element
    auto serial_number_buf = cert_seq.next();
    if (serial_number_buf.id() == x509_version_tag) {
        // It actually was, grab it and move the serial number buffer to the correct element
        ver = version{read_version_tag(serial_number_buf)};
        serial_number_buf = cert_seq.next();
    }

    auto serial_number = asn1::integer{serial_number_buf};

    // signature algo
    auto algo_id = algorithm_id(cert_seq.next());
    auto issuer = name{cert_seq.next()};

    auto validity  = asn1::sequence_view{cert_seq.next()};
    auto notbefore = asn1::utc_time{validity.next()};
    auto notafter  = asn1::utc_time{validity.next()};
    assert(!validity.has_next());

    auto subject = name{cert_seq.next()};

    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //    algorithm            AlgorithmIdentifier,
    //    subjectPublicKey     BIT STRING  }
    auto pk_seq = asn1::sequence_view{cert_seq.next()};
    const auto pk_algo_id = algorithm_id(pk_seq.next());
    // The public key is DER-encoded inside a bit string
    const auto subject_public_key = asn1::bit_string{pk_seq.next()};
    assert(!pk_seq.has_next());
 
    while (cert_seq.has_next()) {
        auto value = cert_seq.next();
        if (value.id() == asn1::identifier::context_specific_tag_1) {
            assert(ver == version::v2 || ver == version::v3);
        } else if (value.id() == asn1::identifier::context_specific_tag_2) {
            assert(ver == version::v2 || ver == version::v3);
        } else if (value.id() == asn1::identifier::context_specific_tag_3) {
            assert(ver == version::v3);
        } else {
            std::ostringstream oss;
            oss << "Unknown tag found in " << __PRETTY_FUNCTION__ << ": " << value;
            throw std::runtime_error(oss.str());
        }
    }

    return tbs_certificate{
        ver,
        serial_number,
        algo_id,
        issuer,
        notbefore,
        notafter,
        subject,
        pk_algo_id,
        subject_public_key
    };
}

certificate certificate::parse(const asn1::der_encoded_value& repr)
{
    auto cert_seq       = asn1::sequence_view{repr};
    auto tbs_cert_val   = cert_seq.next();
    // Save certificate data for verification against the signature
    auto tbsCertificate = buffer_copy(tbs_cert_val.complete_view());
    auto tbs_cert       = parse_tbs_certificate(tbs_cert_val);
    auto sig_algo       = algorithm_id(cert_seq.next());
    auto sig_value      = asn1::bit_string{cert_seq.next()};
    FUNTLS_CHECK_BINARY(cert_seq.has_next(), ==, false, "Extra data found at end of X509 certificate");
    return certificate{std::move(tbs_cert), std::move(tbsCertificate), std::move(sig_algo), std::move(sig_value)};
 }

} } // namespace funtls::x509
