#include <iosfwd>

#include <util/base_conversion.h>
#include <util/buffer.h>
#include <asn1/asn1.h>

namespace funtls { namespace x509 {

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

    tag type() const { return tag_; }

private:
    tag tag_;
};

std::ostream& operator<<(std::ostream& os, const attribute_type& attr);

} } // namespace funtls::x509
