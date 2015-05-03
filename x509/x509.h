#ifndef FUNTLS_X509_X509_H_INCLUDED
#define FUNTLS_X509_X509_H_INCLUDED

#include <iosfwd>
#include <cassert>
#include <map>

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
        locality_name = 7,
        state_or_province_name = 8,
        //streetAddress = 9,
        organization_name = 10,
        organizational_unit_name = 11,
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
        //pseudonym = 65,

        // XXX: HACK: FIXME:
        // https://www.ietf.org/rfc/rfc2459
        // pkcs-9 OBJECT IDENTIFIER   ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
        // emailAddress AttributeType ::= { pkcs-9 1 }
        email_address = 1000+1,
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

    version(tag t = v1) : tag_(t) {
        assert(t == v1 || t == v2 || t == v3);
    }

    enum tag tag() const {
        return tag_;
    }
private:
    enum tag tag_;
};

inline bool operator==(const version& lhs, const version& rhs) {
    return lhs.tag() == rhs.tag();
}

inline bool operator!=(const version& lhs, const version& rhs) {
    return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& os, const version& attr);

class name {
public:
    typedef std::vector<std::pair<attribute_type, std::string>> attr_type;

    name(const asn1::der_encoded_value& repr);

    attr_type attributes() const { return attributes_; }

private:
    attr_type attributes_;
};

inline bool operator==(const name& lhs, const name& rhs) {
    return lhs.attributes() == rhs.attributes();
}

inline bool operator!=(const name& lhs, const name& rhs) {
    return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& os, const name& n);

class algorithm_id {
public:
    algorithm_id(const asn1::der_encoded_value& repr);

    const asn1::object_id& id() const {
        return id_;
    }

    bool null_parameters() const;

    const std::vector<uint8_t>& parameters() const {
        return parameters_;
    }
private:
    asn1::object_id id_;
    std::vector<uint8_t> parameters_;
};

inline bool operator==(const algorithm_id& lhs, const algorithm_id& rhs) {
    if (lhs.id() != rhs.id()) return false;
    if (lhs.null_parameters()) return rhs.null_parameters();
    if (rhs.null_parameters()) return false;
    return lhs.parameters() == rhs.parameters();
}

inline bool operator!=(const algorithm_id& lhs, const algorithm_id& rhs) {
    return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& os, const algorithm_id& aid);

// TBS = To Be Signed
struct tbs_certificate {
    x509::version    version;
    asn1::integer    serial_number;
    algorithm_id     signature_algorithm;
    name             issuer;
    asn1::utc_time   validity_not_before;
    asn1::utc_time   validity_not_after;
    name             subject;
    algorithm_id     subject_public_key_algo;
    asn1::bit_string subject_public_key;
};

struct certificate {
public:
    static certificate parse(const asn1::der_encoded_value&);

    const tbs_certificate& tbs() const {
        return tbs_certificate_;
    }

    const std::vector<uint8_t>& certificate_der_encoded() const {
        return tbs_certificate_der_encoded_;
    }

    const algorithm_id& signature_algorithm() const {
        return signature_algorithm_;
    }

    const asn1::bit_string signature() const {
        return signature_;
    }

private:
    certificate(tbs_certificate&& tbs_cert, std::vector<uint8_t>&& encoded_cert, algorithm_id&& sig_alg, asn1::bit_string&& sig)
        : tbs_certificate_(std::move(tbs_cert))
        , tbs_certificate_der_encoded_(std::move(encoded_cert))
        , signature_algorithm_(sig_alg)
        , signature_(sig) {
    }

    tbs_certificate         tbs_certificate_;
    std::vector<uint8_t>    tbs_certificate_der_encoded_;
    algorithm_id            signature_algorithm_;
    asn1::bit_string        signature_;
};

std::ostream& operator<<(std::ostream& os, const x509::certificate& cert);

static const asn1::object_id id_rsaEncryption{1,2,840,113549,1,1,1};
static const asn1::object_id id_ecPublicKey{1,2,840,10045,2,1}; // https://tools.ietf.org/html/rfc5480

static const asn1::object_id id_sha1WithRSAEncryption{1,2,840,113549,1,1,5};
static const asn1::object_id id_sha256WithRSAEncryption{1,2,840,113549,1,1,11};

static const asn1::object_id id_sha256{2,16,840,1,101,3,4,2,1};
static const asn1::object_id id_sha1{1,3,14,3,2,26};

} } // namespace funtls::x509

#endif
