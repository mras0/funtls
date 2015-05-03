#ifndef FUNTLS_X509_X509_H_INCLUDED
#define FUNTLS_X509_X509_H_INCLUDED

#include <iosfwd>
#include <cassert>
#include <map>

#include <asn1/asn1.h>

namespace funtls { namespace x509 {

struct attribute_type {
    explicit attribute_type(const asn1::der_encoded_value& repr);
    explicit attribute_type(const asn1::object_id& oid) : oid_(oid) {}

    operator asn1::object_id() const {
        return oid_;
    }

private:
    asn1::object_id oid_;
};
// Defined in https://tools.ietf.org/html/rfc5280 A.1
// joint-iso-ccitt(2) ds(5) 4 
static const attribute_type attr_commonName{             asn1::object_id{2,5,4,3}              };
static const attribute_type attr_countryName{            asn1::object_id{2,5,4,6}              };
static const attribute_type attr_localityName{           asn1::object_id{2,5,4,7}              };
static const attribute_type attr_stateOrProvinceName{    asn1::object_id{2,5,4,8}              };
static const attribute_type attr_organizationName{       asn1::object_id{2,5,4,10}             };
static const attribute_type attr_organizationalUnitName{ asn1::object_id{2,5,4,11}             };
static const attribute_type attr_emailAddress{           asn1::object_id{1,2,840,113549,1,9,1} };

inline bool operator==(const attribute_type& lhs, const attribute_type& rhs) {
    return static_cast<asn1::object_id>(lhs) == static_cast<asn1::object_id>(rhs);
}

inline bool operator!=(const attribute_type& lhs, const attribute_type& rhs) {
    return !(lhs == rhs);
}

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
    typedef std::vector<std::pair<attribute_type, asn1::any_string>> attr_type;

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

struct extension {
    asn1::object_id    id;
    asn1::boolean      critical;
    asn1::octet_string value;
};

std::ostream& operator<<(std::ostream& os, const extension& ext);

// TBS = To Be Signed
struct tbs_certificate {
    x509::version          version;
    asn1::integer          serial_number;
    algorithm_id           signature_algorithm;
    name                   issuer;
    asn1::utc_time         validity_not_before;
    asn1::utc_time         validity_not_after;
    name                   subject;
    algorithm_id           subject_public_key_algo;
    asn1::bit_string       subject_public_key;
    std::vector<extension> extensions; // Only present in v3
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

std::ostream& operator<<(std::ostream& os, const certificate& cert);

static const asn1::object_id id_rsaEncryption{1,2,840,113549,1,1,1};
static const asn1::object_id id_ecPublicKey{1,2,840,10045,2,1}; // https://tools.ietf.org/html/rfc5480

static const asn1::object_id id_md2WithRSAEncryption{1,2,840,113549,1,1,2};
static const asn1::object_id id_sha1WithRSAEncryption{1,2,840,113549,1,1,5};
static const asn1::object_id id_sha256WithRSAEncryption{1,2,840,113549,1,1,11};

static const asn1::object_id id_sha256{2,16,840,1,101,3,4,2,1};
static const asn1::object_id id_sha1{1,3,14,3,2,26};

} } // namespace funtls::x509

#endif
