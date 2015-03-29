#include "x509.h"
#include <util/test.h>
#include <ostream>

namespace {

funtls::x509::attribute_type::tag tag_from_oid(const funtls::asn1::object_id& oid)
{
    FUNTLS_CHECK_BINARY(oid.size(), ==, 4, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[0], ==, 2, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[1], ==, 5, "Invalid X509 attribute " + oid.as_string());
    FUNTLS_CHECK_BINARY(oid[2], ==, 4, "Invalid X509 attribute " + oid.as_string());
    return static_cast<funtls::x509::attribute_type::tag>(oid[3]);
}

} // unnamed namespace

namespace funtls { namespace x509 {

attribute_type::attribute_type(const asn1::der_encoded_value& repr)
    : tag_(tag_from_oid(asn1::object_id{repr}))
{
}

std::ostream& operator<<(std::ostream& os, const attribute_type& attr) {
    switch (attr.type()) {
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
        os << "Unknown " << static_cast<uint32_t>(attr.type());
        break;
    }
    return os;
}

} } // namespace funtls::x509
