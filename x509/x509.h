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

    void serialize(std::vector<uint8_t>& buf) const {
        oid_.serialize(buf);
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
    enum tag : uint8_t { v1 = 0, v2 = 1, v3 = 2 };

    version(tag t = v1) : tag_(t) {
        assert(t == v1 || t == v2 || t == v3);
    }

    explicit version(const asn1::der_encoded_value& repr);

    enum tag tag() const {
        return tag_;
    }

    void serialize(std::vector<uint8_t>& buf) const;
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
    using attribute_pair = std::pair<attribute_type, asn1::any_string>;
    typedef std::vector<attribute_pair> attr_type;

    explicit name(std::initializer_list<attribute_pair> attributes) : attributes_(attributes) {}
    explicit name(const asn1::der_encoded_value& repr);

    attr_type attributes() const { return attributes_; }

    void serialize(std::vector<uint8_t>& buf) const;
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
    explicit algorithm_id(const asn1::object_id& id, const std::vector<uint8_t>& parameters = {static_cast<uint8_t>(asn1::identifier::null), 0x00})
        : id_(id)
        , parameters_(parameters) {
        assert(null_parameters());
    }
    algorithm_id(const asn1::der_encoded_value& repr);

    const asn1::object_id& id() const {
        return id_;
    }

    bool null_parameters() const;

    const std::vector<uint8_t>& parameters() const {
        return parameters_;
    }

    void serialize(std::vector<uint8_t>& buf) const;
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

    void serialize(std::vector<uint8_t>& buf) const;
};
std::ostream& operator<<(std::ostream& os, const tbs_certificate& c);
tbs_certificate parse_tbs_certificate(const asn1::der_encoded_value& repr);

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


//
// Checks the signature of the X509 v3 certificate 'subject_cert' against the issuers certificate
// 'issuer_cert' (Note: ONLY against this issuer, i.e. the validity of the issuers certificate is
// NOT verified).
// NOTE: validaty dates are not yet checked (as are probably lots of other stuff)
// Throws an exception if the verification failed.
//
void verify_x509_signature(const certificate& subject_cert, const certificate& issuer_cert);

//
// Checks the trust chain backwards from the last element of 'chain' to the first
// Ending with a self-signed root certificate. NOTE: The chain must contain at least
// 2 elements.
// NOTE: validaty dates are not yet checked (as well of lots and lots of other things)
//
void verify_x509_certificate_chain(const std::vector<certificate>& chain);

static const asn1::object_id id_rsaEncryption{1,2,840,113549,1,1,1};
static const asn1::object_id id_ecPublicKey{1,2,840,10045,2,1}; // https://tools.ietf.org/html/rfc5480

static const asn1::object_id id_md2WithRSAEncryption{1,2,840,113549,1,1,2};
static const asn1::object_id id_md5WithRSAEncryption{1,2,840,113549,1,1,4};
static const asn1::object_id id_sha1WithRSAEncryption{1,2,840,113549,1,1,5};
static const asn1::object_id id_sha256WithRSAEncryption{1,2,840,113549,1,1,11};
static const asn1::object_id id_sha384WithRSAEncryption{1,2,840,113549,1,1,12};
static const asn1::object_id id_sha512WithRSAEncryption{1,2,840,113549,1,1,13};

static const asn1::object_id id_ecdsaWithSHA256{1,2,840,10045,4,3,2};
static const asn1::object_id id_ecdsaWithSHA384{1,2,840,10045,4,3,3};
static const asn1::object_id id_ecdsaWithSHA512{1,2,840,10045,4,3,4};

static const asn1::object_id id_md5{1,2,840,113549,2,5};
static const asn1::object_id id_sha1{1,3,14,3,2,26};
static const asn1::object_id id_sha256{2,16,840,1,101,3,4,2,1};
static const asn1::object_id id_sha384{2,16,840,1,101,3,4,2,2};
static const asn1::object_id id_sha512{2,16,840,1,101,3,4,2,3};

asn1::object_id public_key_algo_from_signature_algo(const algorithm_id& sig_algo);

// X509v3 certificate extensions
static const asn1::object_id id_ce_subjectKeyIdentifier{2,5,29,14};
static const asn1::object_id id_ce_keyUsage{2,5,29,15};
static const asn1::object_id id_ce_subjectAltName{2,5,29,17};
static const asn1::object_id id_ce_basicConstraints{2,5,29,19};

// Actually PKCS#1 RFC3447 stuff:
template<typename IntType, typename Iterator>
IntType base256_decode(Iterator first, Iterator last)
{
    IntType res = 0;
    for (; first != last; ++first) {
        res <<= 8;
        res |= *first;
    }
    return res;
}

template<typename IntType, size_t sz>
IntType base256_decode(const uint8_t (&arr)[sz])
{
    return base256_decode<IntType>(arr, arr+sz);
}

template<typename IntType>
IntType base256_decode(const std::vector<uint8_t>& bs)
{
    return base256_decode<IntType>(bs.begin(), bs.end());
}

template<typename IntType>
IntType base256_decode(const asn1::raw_string& r)
{
    return base256_decode<IntType>(r.as_vector());
}

template<typename IntType>
std::vector<uint8_t> base256_encode(IntType i, size_t byte_count)
{
    std::vector<uint8_t> result(byte_count);
    while (byte_count--) {
        result[byte_count] = static_cast<uint8_t>(i);
        i >>= 8;
    }
    assert(i == 0);
    return result;
}

template<typename T>
T from_buffer(const std::vector<uint8_t>& b)
{
    assert(!b.empty());
    util::buffer_view view(b.data(), b.size());
    return T(asn1::read_der_encoded_value(view));
}


struct private_key_info {
    asn1::integer       version;
    x509::algorithm_id  algorithm;
    asn1::octet_string  key;

    static private_key_info parse(const asn1::der_encoded_value&);
};
std::ostream& operator<<(std::ostream& os, const private_key_info& pki);

} } // namespace funtls::x509

#endif
