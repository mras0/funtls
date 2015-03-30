#include "x509.h"
#include <util/test.h>
#include <ostream>

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
    throw std::logic_error("Should be unreachable in " + std::string(__PRETTY_FUNCTION__));
}

funtls::x509::version::tag read_tag(const funtls::asn1::der_encoded_value& repr)
{
    FUNTLS_CHECK_BINARY(repr.id(), ==, funtls::asn1::identifier::context_specific_tag_0, "Expected X509 version element");
    auto ver_content = repr.content_view();
    auto ver_int = funtls::asn1::integer{funtls::asn1::read_der_encoded_value(ver_content)};
    FUNTLS_CHECK_BINARY(ver_content.remaining(), ==, 0, "Extra content at end of X509 version element");
    return version_tag_from_int(ver_int);
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
        os << "Common name";
        break;
    case attribute_type::country_name:
        os << "Country";
        break;
    case attribute_type::state_or_province_name:
        os << "State/Province";
        break;
    case attribute_type::organization_name:
        os << "Organization";
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

} } // namespace funtls::x509
