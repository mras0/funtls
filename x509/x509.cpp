#include "x509.h"
#include <util/test.h>
#include <util/base_conversion.h>
#include <ostream>
#include <algorithm>

using namespace funtls;

namespace {

constexpr auto x509_version_tag = funtls::asn1::identifier::context_specific_tag_0;

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
            res.push_back(std::make_pair(attribute_type, asn1::any_string(value)));
            if (av_pair.has_next()) {
                FUNTLS_CHECK_FAILURE("Excess data in X509 name attribute type/value pair");
            }
        }
        // end of RelativeDistinguishedName
    }
    return res;
}

std::vector<x509::extension> parse_extensions(const asn1::der_encoded_value& value)
{
    std::vector<x509::extension> ret;
    auto extensions = asn1::sequence_view{value};
    do {
        auto ext = asn1::sequence_view{extensions.next()};
        auto extnID = asn1::object_id{ext.next()};
        auto next_elem = ext.next();
        asn1::boolean critical{0};
        if (next_elem.id() == asn1::identifier::boolean) {
            critical  = asn1::boolean{next_elem};
            next_elem = ext.next();
        }
        auto extnValue = asn1::octet_string{next_elem};
        FUNTLS_CHECK_BINARY(ext.has_next(), ==, false, "Extra data at end of extension element");
        ret.push_back(x509::extension{std::move(extnID), std::move(critical), std::move(extnValue)});
    } while (extensions.has_next());

    return ret;
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
    : attribute_type(asn1::object_id{repr})
{
}

std::ostream& operator<<(std::ostream& os, const attribute_type& attr)
{
    if (attr == attr_commonName) {
        return os << "CN";
    } else if (attr == attr_countryName) {
        return os << "C";
    } else if (attr == attr_localityName) {
        return os << "L";
    } else if (attr == attr_stateOrProvinceName) {
        return os << "ST";
    } else if (attr == attr_organizationName) {
        return os << "O";
    } else if (attr == attr_organizationalUnitName) {
        return os << "OU";
    } else if (attr == attr_emailAddress) {
        return os << "E";
    }
    return os << "AttributeType<" << static_cast<asn1::object_id>(attr) << ">";
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
    if (parameters_.size() == 2 && parameters_[0] == asn1::identifier::null && parameters_[1] == 0) {
        return true;
    }
    return false;
}

std::ostream& operator<<(std::ostream& os, const algorithm_id& aid)
{
    const auto& id = aid.id();
    if (id == id_rsaEncryption){
        os << "rsaEncryption";
    } else if (id == id_ecPublicKey){
        os << "ecPublicKey";
    } else if (id == id_md2WithRSAEncryption){
        os << "md2WithRSAEncryption";
    } else if (id == id_md5WithRSAEncryption){
        os << "md5WithRSAEncryption";
    } else if (id == id_sha1WithRSAEncryption){
        os << "sha1WithRSAEncryption";
    } else if (id == id_sha256WithRSAEncryption){
        os << "sha256WithRSAEncryption";
    } else if (id == id_sha384WithRSAEncryption){
        os << "sha384WithRSAEncryption";
    } else if (id == id_sha512WithRSAEncryption){
        os << "sha512WithRSAEncryption";
    } else if (id == id_sha1){
        os << "sha1";
    } else if (id == id_sha256){
        os << "sha256";
    } else if (id == id_sha384){
        os << "sha384";
    } else if (id == id_sha512){
        os << "sha512";
    } else {
        os << aid.id();
    }
    if (!aid.null_parameters()) {
        os << "[parameters: " << util::base16_encode(aid.parameters()) << "]";
    }
    return os;
}

namespace {

std::string handle_subjectKeyIdentifier(util::buffer_view& buf) {
    asn1::octet_string key_identifier{asn1::read_der_encoded_value(buf)};
    return "SubjectKeyIdentifier " + util::base16_encode(key_identifier.as_vector());
}

std::string handle_keyUsage(util::buffer_view& buf) {
    auto bs = asn1::bit_string{asn1::read_der_encoded_value(buf)};

    static const char* const bit_meaning[] = {
           "digitalSignature",
           "nonRepudiation", //-- recent editions of X.509 have renamed this bit to contentCommitment
           "keyEncipherment",
           "dataEncipherment",
           "keyAgreement",
           "keyCertSign",
           "cRLSign",
           "encipherOnly",
           "decipherOnly",
    };
    std::ostringstream oss;
    oss << "KeyUsage";
    const auto& r = bs.repr();
    for (size_t i = 0; i < bs.bit_count(); ++i) {
        const auto byte = i >> 3;
        const auto bit  = 7 - (i & 7);
        assert(byte < r.size());
        if (r[byte] & (1<<bit)) {
            FUNTLS_CHECK_BINARY(i, <, sizeof(bit_meaning)/sizeof(bit_meaning[0]), "Unknown KeyUsage bit");
            oss << " " << bit_meaning[i];
        }
    }

    return oss.str();
}

std::string handle_basicConstraints(util::buffer_view& buf) {
    // BasicConstraintsSyntax ::= SEQUENCE {
    // 	cA	BOOLEAN DEFAULT FALSE,
    // 	pathLenConstraint INTEGER (0..MAX) OPTIONAL
    // }
    asn1::sequence_view seq{asn1::read_der_encoded_value(buf)};
    std::ostringstream oss;
    oss << "BasicConstraints";
    if (seq.has_next()) {
        auto elem = seq.next();
        if (elem.id() == asn1::identifier::boolean) {
            oss << " cA=" << (asn1::boolean{elem} ? "true" : "false");
            if (!seq.has_next()) goto done;
            elem = seq.next();
        }
        oss << " pathLenConstraint=" << asn1::integer{elem}.as<long long>();
    }
done:
    return oss.str();
}

const struct {
    asn1::object_id id;
    std::string   (*format_string)(util::buffer_view&);
} extension_handlers[] = {
    { id_ce_subjectKeyIdentifier ,&handle_subjectKeyIdentifier },
    { id_ce_keyUsage             ,&handle_keyUsage },
    { id_ce_basicConstraints     ,&handle_basicConstraints },
};

}

std::ostream& operator<<(std::ostream& os, const extension& e)
{
    for (const auto& h : extension_handlers) {
        if (h.id != e.id) {
            continue;
        }
        auto buf = e.value.as_vector();
        FUNTLS_CHECK_BINARY(buf.size(), >, 0, "Empty extension value");
        util::buffer_view bv{&buf[0], buf.size()};
        os << h.format_string(bv);
        FUNTLS_CHECK_BINARY(bv.remaining(), ==, 0, "Extension parsed incorectly");
        return os;
    }
    return os << "<Extension " << e.id << (e.critical ? "! " : "  ") << util::base16_encode(e.value.as_vector()) << ">";
}

std::ostream& operator<<(std::ostream& os, const certificate& cert)
{
    auto c = cert.tbs();
    os << "Certificate " << c.version << ":\n";
    os << " Serial number: 0x" << util::base16_encode(c.serial_number.as_vector()) << "\n";
    os << " Signature algorithm: " << c.signature_algorithm << " [Actual " << cert.signature_algorithm() << "]\n";
    os << " Issuer: " << c.issuer << "\n";
    os << " Validity: Between " << c.validity_not_before << " and " << c.validity_not_after << "\n";
    os << " Subject: " << c.subject << "\n";
    os << " Subject public key algorithm: " << c.subject_public_key_algo << "\n";
    bool first = true;
    for (const auto ext : c.extensions) {
        if (first) {
            os << "Extensions:\n";
            first = false;
        }
        os << " " << ext << "\n";
    }
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

    std::vector<extension> extensions;

    while (cert_seq.has_next()) {
        auto value = cert_seq.next();
        if (value.id() == asn1::identifier::context_specific_tag_1) {
            // issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL -- If present, version MUST be v2 or v3
            if (ver != version::v2 && ver != version::v3) {
                std::ostringstream msg;
                msg << value.id() << " not expected in version " << ver;
                FUNTLS_CHECK_FAILURE(msg.str());
            }
        } else if (value.id() == asn1::identifier::context_specific_tag_2) {
            // subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL -- If present, version MUST be v2 or v3
            if (ver != version::v2 && ver != version::v3) {
                std::ostringstream msg;
                msg << value.id() << " not expected in version " << ver;
                FUNTLS_CHECK_FAILURE(msg.str());
            }
        } else if (value.id() == asn1::identifier::context_specific_tag_3) {
            //  extensions [3]  EXPLICIT Extensions OPTIONAL -- If present, version MUST be v3
            if (ver != version::v3) {
                std::ostringstream msg;
                msg << value.id() << " not expected in version " << ver;
                FUNTLS_CHECK_FAILURE(msg.str());
            }
            auto extensions_buf = value.content_view();
            extensions = parse_extensions(asn1::read_der_encoded_value(extensions_buf));
            FUNTLS_CHECK_BINARY(extensions_buf.remaining(), ==, 0, "Invalid Extensions[3] element");
        } else {
            std::ostringstream msg;
            msg << "Unknown tag " << value;
            FUNTLS_CHECK_FAILURE(msg.str());
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
        subject_public_key,
        extensions
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
