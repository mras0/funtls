#include <iosfwd>
#include <cassert>
#include <map>

#include <asn1/asn1.h>

namespace funtls { namespace x509 {

static const asn1::object_id rsaEncryption{ 1,2,840,113549,1,1,1 };
static const asn1::object_id sha256WithRSAEncryption{ 1,2,840,113549,1,1,11 };

// Defined in https://tools.ietf.org/html/rfc5280 A.1
// joint-iso-ccitt(2) ds(5) 4 
class attribute_type {
public:
    enum tag : uint32_t {
        //objectClass = 0,
        //aliasedEntryName = 1,
        //knowldgeinformation = 2,
        common_name = 3,
        //surname = 4,
        //serialNumber = 5,
        country_name = 6,
        //localityName = 7,
        state_or_province_name = 8,
        //streetAddress = 9,
        organization_name = 10,
        //organizationalUnitName = 11,
        //title = 12,
        //description = 13,
        //searchGuide = 14,
        //businessCategory = 15,
        //postalAddress = 16,
        //postalCode = 17,
        //postOfficeBox = 18,
        //physicalDeliveryOfficeName = 19,
        //telephoneNumber = 20,
        //telexNumber = 21,
        //teletexTerminalIdentifier = 22,
        //facsimileTelephoneNumber = 23,
        //x121Address = 24,
        //internationalISDNNumber = 25,
        //registeredAddress = 26,
        //destinationIndicator = 27,
        //preferredDeliveryMethod = 28,
        //presentationAddress = 29,
        //supportedApplicationContext = 30,
        //member = 31,
        //owner = 32,
        //roleOccupant = 33,
        //seeAlso = 34,
        //userPassword = 35,
        //userCertificate = 36,
        //cACertificate = 37,
        //authorityRevocationList = 38,
        //certificateRevocationList = 39,
        //crossCertificatePair = 40,
        //name = 41,
        //givenName = 42,
        //initials = 43,
        //generationQualifier = 44,
        //uniqueIdentifier = 45,
        //dnQualifier = 46,
        //enhancedSearchGuide = 47,
        //protocolInformation = 48,
        //distinguishedName = 49,
        //uniqueMember = 50,
        //houseIdentifier = 51,
        //supportedAlgorithms = 52,
        //deltaRevocationList = 53,
        //    Attribute Certificate attribute (attributeCertificate) = 58
        pseudonym = 65,
    };

    attribute_type(const asn1::der_encoded_value& repr);
    attribute_type(tag t) : tag_(t) {}

    operator tag() const {
        return tag_;
    }

private:
    tag tag_;
};

std::ostream& operator<<(std::ostream& os, const attribute_type& attr);

class version {
public:
    enum tag { v1 = 0, v2 = 1, v3 = 2 };
    version(const asn1::der_encoded_value& repr);
    version(tag t) : tag_(t) {
        assert(t == v1 || t == v2 || t == v3);
    }

    operator tag() const {
        return tag_;
    }
private:
    tag tag_;
};

std::ostream& operator<<(std::ostream& os, const version& attr);

class name {
public:
    typedef std::vector<std::pair<attribute_type, std::string>> attr_type;

    name(const asn1::der_encoded_value& repr);

    attr_type attributes() const { return attributes_; }

private:
    attr_type attributes_;
};

std::ostream& operator<<(std::ostream& os, const name& n);

struct rsa_public_key {
    asn1::integer modolus;           // n
    asn1::integer public_exponent;   // e
};

struct v3_certificate {
    asn1::integer   serial_number;
    asn1::object_id signature_algorithm;
    name            issuer;
    asn1::utc_time  validity_not_before;
    asn1::utc_time  validity_not_after;
    name            subject;
    rsa_public_key  subject_public_key;
};

v3_certificate parse_v3_cert(const asn1::der_encoded_value& repr);

asn1::object_id read_algorithm_identifer(const asn1::der_encoded_value& value);

} } // namespace funtls::x509
