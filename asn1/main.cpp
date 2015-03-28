#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cassert>
#include <iomanip>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

std::string hexstring(const void* buffer, size_t len)
{
    const uint8_t* bytes = static_cast<const uint8_t*>(buffer);
    assert(len <= len*2);
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        static const char* const hexchars = "0123456789abcdef";
        result += hexchars[bytes[i] >> 4];
        result += hexchars[bytes[i] & 0xf];
    }
    return result;
}

struct buffer_view {
    buffer_view(const uint8_t* buffer, size_t size) : buffer_(buffer), size_(size), index_(0) {
    }

    size_t size() const {
        return size_;
    }

    size_t remaining() const {
        assert(index_ <= size_);
        return size_ - index_;
    }

    void skip(size_t num_bytes) {
        if (index_ + num_bytes > size_) throw std::runtime_error("Out of data in " + std::string(__PRETTY_FUNCTION__));
        index_ += num_bytes;
    }

    uint8_t get() {
        if (index_ + 1 > size_) throw std::runtime_error("Out of data in " + std::string(__PRETTY_FUNCTION__));
    //    std::cout << "<<" << hexstring(&buffer_[index_], 1) << ">>";
        return buffer_[index_++];
    }

    void get_many(void* dest, size_t num_bytes) {
        if (index_ + num_bytes > size_) throw std::runtime_error("Out of data in " + std::string(__PRETTY_FUNCTION__));
        memcpy(dest, &buffer_[index_], num_bytes);
        index_ += num_bytes;
    }

    buffer_view get_slice(size_t slice_size) {
        if (index_ + slice_size > size_) throw std::runtime_error("Out of data in " + std::string(__PRETTY_FUNCTION__));
        const uint8_t* slice_buffer = buffer_ + index_;
        index_ += slice_size;
        return buffer_view(slice_buffer, slice_size);
    }

private:
    const uint8_t* buffer_;
    size_t         size_;
    size_t         index_;
};

class asn1_identifier {
public:
    static constexpr uint8_t constructed_bit = 0x20;
    enum asn1_tag : uint8_t {
        integer              = 0x02,
        bit_string           = 0x03,
        null                 = 0x05,
        object_id            = 0x06,
        utf8_string          = 0x0C,
        sequence             = 0x10,
        set                  = 0x11,
        printable_string     = 0x13,
        utc_time             = 0x17,
        constructed_sequence = sequence | constructed_bit,
        constructed_set      = set      | constructed_bit,
    };

    asn1_identifier(uint8_t value) : repr_(value) {
    }

    explicit operator uint8_t() const {
        return repr_;
    }

    bool operator==(const asn1_identifier& rhs) const {
        return repr_ == rhs.repr_;
    }

    bool operator!=(const asn1_identifier& rhs) const {
        return !(*this == rhs);
    }

    asn1_identifier operator|(uint8_t mask) const {
        assert(!(mask&0x1f));
        return asn1_identifier{static_cast<uint8_t>(repr_ | mask)};
    }

    static asn1_identifier tagged(uint8_t tag) {
        return tag | (2<<6); // context specific
    }

    friend std::ostream& operator<<(std::ostream& os, const asn1_identifier& ident) {
        uint8_t id = ident.repr_;
        uint8_t clazz = (id >> 6) & 3;
        bool    constructed = (id & asn1_identifier::constructed_bit) != 0;
        uint8_t tag = id & 0x1f;
        static const char* const clazz_name[] = { "universal", "application", "context-specific", "private" };
        os << "<identifier 0x" <<  hexstring(&id, 1);
        os << " " << clazz_name[clazz];
        os << " " << (constructed ? "constructed" : "primitive");
        os << " " << static_cast<unsigned>(tag);
        os << ">";
        return os;
    }
private:
    uint8_t repr_;
};

asn1_identifier read_asn1_identifier(buffer_view& buf)
{
    uint8_t id = buf.get();
    // If the identifier is not universal, its tag may be a number that is greater than 30. 
    // In that case, the tag does not fit in the 5-bit tag field, and must be encoded in subsequent octets. 
    // The value 11111 is reserved for identifying such encodings.
    assert((id&0x1f)!=31);
    return asn1_identifier{id};
}

size_t read_asn1_length(buffer_view& buf)
{
    const uint8_t first_size_byte = buf.get();
    if (first_size_byte & 0x80) {
        const uint8_t length_octets = first_size_byte & 0x7f;
        if (length_octets == 0x7f) throw std::runtime_error("Illegal length octet");
        if (length_octets > sizeof(size_t)) throw std::runtime_error("Unsupported length octet count " + std::to_string(length_octets));
        size_t sz = 0;
        for (unsigned i = 0; i < length_octets; ++i) {
            sz <<= 8;
            sz |= buf.get();
        }
        return sz;
    } else {
        return first_size_byte & 0x7f;
    }
}

buffer_view asn1_expect_id(buffer_view& buf, asn1_identifier expected_id)
{
    const auto id = read_asn1_identifier(buf);
    if (id != expected_id) {
        throw std::runtime_error(std::string(__PRETTY_FUNCTION__) + ": " + std::to_string(uint8_t(id)) + " is not expected id " + std::to_string(uint8_t(expected_id)));
    }

    const auto len = read_asn1_length(buf);
    return buf.get_slice(len);
}

int_type asn1_read_integer(buffer_view& buf)
{
    auto int_buf = asn1_expect_id(buf, asn1_identifier::integer);
    if (int_buf.size() < 1 || int_buf.size() > 1000) {
        throw std::runtime_error("Invalid integer size " + std::to_string(int_buf.size()) + " in " + __PRETTY_FUNCTION__);
    }
    int_type val = static_cast<int8_t>(int_buf.get()); // assumes native 2's complement notation
    for (size_t i = 1; i < int_buf.size(); ++i) {
        val <<= 8;
        val |= int_buf.get();
    }
    return val;
}

bool asn1_is_valid_printable_character(char c)
{
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= '0' && c <= '9') return true;
    for (const char* check_char = " '()+,-./:=?"; *check_char; ++check_char) {
        if (*check_char == c) return true;
    }
    return false;
}

class asn1_object_id {
public:
    asn1_object_id() : components_() {
    }

    asn1_object_id(std::vector<uint32_t> components) : components_(components) {
    }

    asn1_object_id(std::initializer_list<uint32_t> components) : components_(components) {
    }

    size_t size() const {
        return components_.size();
    }

    uint32_t operator[](size_t index) const {
        assert(index < size());
        return components_[index];
    }

    bool operator==(const asn1_object_id& rhs) const {
        return components_ == rhs.components_;
    }

    bool operator!=(const asn1_object_id& rhs) const {
        return !(*this == rhs);
    }

    friend std::ostream& operator<<(std::ostream& os, const asn1_object_id& oid) {
        assert(!oid.components_.empty());
        os << oid.components_[0];
        for (unsigned i = 1; i < oid.components_.size(); ++i) {
            os << "." << oid.components_[i];
        }
        return os;
    }

private:
    std::vector<uint32_t> components_;
};

asn1_object_id asn1_read_object_id(buffer_view& buf)
{
    auto oid_buf = asn1_expect_id(buf, asn1_identifier::object_id);
    if (oid_buf.size() < 1 || oid_buf.size() > 20) { // What are common sizes?
        throw std::runtime_error("Invalid oid size " + std::to_string(oid_buf.size()) + " in " + __PRETTY_FUNCTION__);
    }
    const uint8_t first = oid_buf.get();
    std::vector<uint32_t> res;
    /*
       The first octet has value 40 * value1 + value2.
       (This is unambiguous, since value1 is limited to values 0, 1, and 2; value2 is limited to the 
       range 0 to 39 when value1 is 0 or 1; and, according to X.208, n is always at least 2.)
    */
    res.push_back(first/40);
    res.push_back(first%40);

    /*
       The following octets, if any, encode value3, ..., valuen. Each value is encoded base 128, 
       most significant digit first, with as few digits as possible, and the most significant bit 
       of each octet except the last in the value's encoding set to "1."*
       }
    */
    while (oid_buf.remaining()) {
        uint32_t value = 0;
        uint8_t read_byte = 0;
        do {
            if (value >= (1<<21)) {
                // OIDs must be less than 2^28, so if the value before shifting by 7 is >= 2^21
                // it is about to become out of range
                throw std::runtime_error("OID value out of range in " + std::string(__PRETTY_FUNCTION__));
            }
            read_byte = oid_buf.get();
            value <<= 7;
            value |= read_byte & 0x7f;
        } while (read_byte & 0x80);
        res.push_back(value);
    }

    assert(oid_buf.remaining() == 0);
    return res;
}

void print_all(buffer_view& buf, const char* name)
{
    while (buf.remaining()) {
        // identifer, length, content, end-of-content

        auto id = read_asn1_identifier(buf);
        auto len = read_asn1_length(buf);

        std::cout << name << " len=" << std::setw(4) << len << " " << id << std::endl;
        buf.skip(len);
    }
}
enum class x500_attribute_type : uint32_t {
    objectClass = 0,
    aliasedEntryName = 1,
    knowldgeinformation = 2,
    commonName = 3,
    surname = 4,
    serialNumber = 5,
    countryName = 6,
    localityName = 7,
    stateOrProvinceName = 8,
    streetAddress = 9,
    organizationName = 10,
    organizationalUnitName = 11,
    title = 12,
    description = 13,
    searchGuide = 14,
    businessCategory = 15,
    postalAddress = 16,
    postalCode = 17,
    postOfficeBox = 18,
    physicalDeliveryOfficeName = 19,
    telephoneNumber = 20,
    telexNumber = 21,
    teletexTerminalIdentifier = 22,
    facsimileTelephoneNumber = 23,
    x121Address = 24,
    internationalISDNNumber = 25,
    registeredAddress = 26,
    destinationIndicator = 27,
    preferredDeliveryMethod = 28,
    presentationAddress = 29,
    supportedApplicationContext = 30,
    member = 31,
    owner = 32,
    roleOccupant = 33,
    seeAlso = 34,
    userPassword = 35,
    userCertificate = 36,
    cACertificate = 37,
    authorityRevocationList = 38,
    certificateRevocationList = 39,
    crossCertificatePair = 40,
    name = 41,
    givenName = 42,
    initials = 43,
    generationQualifier = 44,
    uniqueIdentifier = 45,
    dnQualifier = 46,
    enhancedSearchGuide = 47,
    protocolInformation = 48,
    distinguishedName = 49,
    uniqueMember = 50,
    houseIdentifier = 51,
    supportedAlgorithms = 52,
    deltaRevocationList = 53,
    //    Attribute Certificate attribute (attributeCertificate) = 58
    pseudonym = 65,
};

std::ostream& operator<<(std::ostream& os, const x500_attribute_type& attr) {
    switch (attr) {

    case x500_attribute_type::commonName:
        os << "Common name";
        break;
    case x500_attribute_type::countryName:
        os << "Country";
        break;
    case x500_attribute_type::stateOrProvinceName:
        os << "State/Province";
        break;
    case x500_attribute_type::organizationName:
        os << "Organization";
        break;
    default:
        os << "Unknown " << static_cast<uint32_t>(attr);
        break;
    }
    return os;
}

void parse_Name(buffer_view& buf)
{

    // Name ::= CHOICE { RDNSequence }
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName 
    // RelativeDistinguishedName ::= SET OF AttributeValueAssertion
    // AttributeValueAssertion ::= SEQUENCE { AttributeType, AttributeValue }
    // AttributeType ::= OBJECT IDENTIFIER
    auto name_buf = asn1_expect_id(buf, asn1_identifier::constructed_sequence); // RDNSequence
    while (name_buf.remaining()) {
        auto rdn_buf = asn1_expect_id(name_buf, asn1_identifier::constructed_set);
        while (rdn_buf.remaining()) {
            auto av_pair_buf = asn1_expect_id(rdn_buf, asn1_identifier::constructed_sequence);
            auto attribute_type = asn1_read_object_id(av_pair_buf);

            // 2.5.4 - X.500 attribute types
            // http://www.alvestrand.no/objectid/2.5.4.html
            if (attribute_type.size() != 4 || attribute_type[0] != 2 || attribute_type[1] != 5 || attribute_type[2] != 4) {
                std::ostringstream oss;
                oss << "Invalid attribute found in " << __PRETTY_FUNCTION__ << ": " << attribute_type;
                throw std::runtime_error(oss.str());
            }
            const auto x500_attr_type = static_cast<x500_attribute_type>(attribute_type[3]);
            auto id = read_asn1_identifier(av_pair_buf);
            auto len = read_asn1_length(av_pair_buf);
            const size_t name_max_length = 200;
            if (len < 1 || len > name_max_length) {
                throw std::runtime_error("Invalid length found in " + std::string(__PRETTY_FUNCTION__) + " id=" + std::to_string((uint8_t)id) + " len=" + std::to_string(len));
            }
            if (id == asn1_identifier::printable_string || id == asn1_identifier::utf8_string) {
                std::string s(len, '\0');
                if (len) av_pair_buf.get_many(&s[0], len);
                // TODO: check that the string is valid
                std::cout << " " << x500_attr_type << ": '" << s << "'" << std::endl;
            } else {
                // Only TeletexString, UniversalString or BMPString allowed here
                throw std::runtime_error("Unknown type found in " + std::string(__PRETTY_FUNCTION__) + " id=" + std::to_string((uint8_t)id) + " len=" + std::to_string(len));
            }
            assert(av_pair_buf.remaining() == 0);
        }
        // end of RelativeDistinguishedName
    }
}

class asn1_utc_time {
public:
    asn1_utc_time(const std::string& s) {
        // Valid formats:
        // 0123456789012345678
        // YYMMDDhhmmZ
        // YYMMDDhhmm+hh'mm'
        // YYMMDDhhmm-hh'mm'
        // YYMMDDhhmmssZ
        // YYMMDDhhmmss+hh'mm'
        // YYMMDDhhmmss-hh'mm'
        if (s.length() < 11 || s.length() > 19) {
            throw std::runtime_error("Invalid length of UTCTime '" + s + "'");
        }
        year   = 2000 + get_2digit_int(&s[0]);
        month  = get_2digit_int_checked(&s[2], 1, 12, "month");
        date   = get_2digit_int_checked(&s[4], 1, 31, "date");
        hour   = get_2digit_int_checked(&s[6], 0, 23, "hour");
        minute = get_2digit_int_checked(&s[8], 0, 59, "minute");
        if (isdigit(s[10])) {
            if (s.length() < 13) {
                throw std::runtime_error("Invalid length of UTCTime '" + s + "'");
            }
            second = get_2digit_int_checked(&s[10], 0, 59, "second");
            tz = std::string(&s[12]);
        } else {
            second = 0;
            tz = std::string(&s[10]);
        }
        // TODO: Check that the date is legal (e.g. no february 31th)
        // TODO: Check that the time zone is valid
    }

    friend std::ostream& operator<<(std::ostream& os, const asn1_utc_time& t) {
        auto fill = os.fill();
        os.fill('0');
        os << std::setw(4) << t.year << "-" << std::setw(2) << t.month << "-" << std::setw(2) << t.date << " ";
        os << std::setw(2) << t.hour << ":" << std::setw(2) << t.minute << ":" << std::setw(2) << t.second << t.tz;
        os.fill(fill);
        return os;
    }

private:
    int year;
    int month;
    int date;
    int hour;
    int minute;
    int second;
    std::string tz;

    static int get_digit(char d) {
        if (d < '0' || d > '9') throw std::runtime_error("Invalid digit found in UTC time: " + std::string(1, d));
        return d - '0';
    }

    static int get_2digit_int(const char* src) {
        return 10 * get_digit(src[0]) + get_digit(src[1]);
    }

    static int get_2digit_int_checked(const char* src, int min, int max, const char* name) {
        int n = get_2digit_int(src);
        if (n < min) throw std::runtime_error(std::string(name) + " is too small " + std::to_string(n) + " < " + std::to_string(min));
        if (n > max) throw std::runtime_error(std::string(name) + " is too large " + std::to_string(n) + " > " + std::to_string(max));
        return n;
    }
};

asn1_utc_time parse_UTCTime(buffer_view& parent_buf)
{
    auto time_buf = asn1_expect_id(parent_buf, asn1_identifier::utc_time);
    std::string s(time_buf.remaining(), '\0');
    if (!s.empty()) time_buf.get_many(&s[0], s.length());
    return s;
}

asn1_object_id asn1_read_algorithm_identifer(buffer_view& parent_buf)
{
    auto algo_buf = asn1_expect_id(parent_buf, asn1_identifier::constructed_sequence);
    auto algo_id = asn1_read_object_id(algo_buf); // algorithm OBJECT IDENTIFIER,
    //parameters  ANY DEFINED BY algorithm OPTIONA
    auto param_id = read_asn1_identifier(algo_buf);
    auto param_len = read_asn1_length(algo_buf);
    if (param_id != asn1_identifier::null || param_len != 0) { // parameters MUST be null for rsaEncryption at least
        std::ostringstream oss;
        oss << "Expected NULL parameter of length 0 in " << __PRETTY_FUNCTION__ << " got " << param_id << " of length " << param_len;
        throw std::runtime_error(oss.str());
    }
    assert(algo_buf.remaining() == 0);
    return algo_id;
}

class asn1_bit_string {
public:
    asn1_bit_string(const std::vector<uint8_t>& data, size_t bit_count) : repr_(data), size_(bit_count) {
        if (bit_count == 0 || bit_count > data.size() * 8 || bit_count < data.size() * 8 - 7) {
            std::ostringstream oss;
            oss << "Invalid bit count " << bit_count << " for data size " << data.size();
            throw std::logic_error(oss.str());
        }
        const size_t remaining = data.size() * 8 - bit_count;
        assert(!remaining || (data[data.size()-1] & ((1<<remaining)-1)) == 0);
    }
    size_t size() const {
        return size_;
    }
    friend std::ostream& operator<<(std::ostream& os, const asn1_bit_string& bs) {
        os << hexstring(&bs.repr_[0], bs.repr_.size());
        return os;
    }

    const uint8_t* data() const {
        return &repr_[0];
    }

private:
    std::vector<uint8_t> repr_;
    size_t               size_;
};

asn1_bit_string asn1_read_bit_string(buffer_view& parent_buf)
{
    auto data_buf = asn1_expect_id(parent_buf, asn1_identifier::bit_string);
    if (data_buf.remaining() < 2) {
        throw std::runtime_error("Too little data in bit string len="+std::to_string(data_buf.remaining()));
    }
    const uint8_t unused_bits = data_buf.get();
    if (unused_bits >= 8) {
        throw std::runtime_error("Invalid number of bits in bit string: "+std::to_string((int)unused_bits));
    }
    std::vector<uint8_t> data(data_buf.remaining());
    data_buf.get_many(&data[0], data.size());
    return {data, data.size()*8-unused_bits};
}

struct rsa_public_key {
    int_type modolus;           // n
    int_type public_exponent;   // e
};

rsa_public_key asn1_read_rsa_public_key(buffer_view& parent_buf)
{
    auto elem_buf = asn1_expect_id(parent_buf, asn1_identifier::constructed_sequence);
    const auto modolus         = asn1_read_integer(elem_buf);
    const auto public_exponent = asn1_read_integer(elem_buf);
    assert(elem_buf.remaining() == 0);
    return rsa_public_key{modolus, public_exponent};
}

class algorithm_info {
public:
    algorithm_info(const std::string& name, const asn1_object_id& algorithm_identifier)
        : name_(name)
        , algorithm_identifier_(algorithm_identifier) {
    }

    std::string    name() const { return name_; }
    asn1_object_id algorithm_identifier() const { return algorithm_identifier_; }

private:
    std::string     name_;
    asn1_object_id  algorithm_identifier_;
};

static const asn1_object_id x509_rsaEncryption{ 1,2,840,113549,1,1,1 };
static const asn1_object_id x509_sha256WithRSAEncryption{ 1,2,840,113549,1,1,11 };

static const algorithm_info x509_algorithms[] = {
    // 1.2.840.113549.1.1 - PKCS-1
    { "rsaEncryption"           , x509_rsaEncryption },
    { "sha256WithRSAEncryption" , x509_sha256WithRSAEncryption  },
};

const algorithm_info& info_from_algorithm_id(const asn1_object_id& oid)
{
    for (const auto& algo : x509_algorithms) {
        if (algo.algorithm_identifier() == oid) {
            return algo;
        }
    }
    std::ostringstream oss;
    oss << "Unknown algorithm identifier " << oid;
    throw std::runtime_error(oss.str());
}

std::ostream& operator<<(std::ostream& os, const algorithm_info& ai)
{
    os << ai.name() << " (" << ai.algorithm_identifier() << ")";
    return os;
}

// https://tools.ietf.org/html/rfc4055
rsa_public_key parse_RSAPublicKey(buffer_view& buf)
{
    auto public_key_buf = asn1_expect_id(buf, asn1_identifier::constructed_sequence);
    const auto pk_algo_id = asn1_read_algorithm_identifer(public_key_buf);
    if (pk_algo_id != x509_rsaEncryption) {
        std::ostringstream oss;
        oss << "Unknown key algorithm id " << pk_algo_id << " expected rsaEncryption (" << x509_rsaEncryption << ") in " << __PRETTY_FUNCTION__;
        throw std::runtime_error(oss.str());
    }
    // The public key is DER-encoded inside a bit string
    auto bs = asn1_read_bit_string(public_key_buf);
    buffer_view pk_buf{bs.data(),bs.size()/8};
    const auto public_key = asn1_read_rsa_public_key(pk_buf);
    assert(public_key_buf.remaining() == 0);
    return public_key;
}

void parse_TBSCertificate(buffer_view& elem_buf)
{
    auto version_buf = asn1_expect_id(elem_buf, asn1_identifier::tagged(0) | asn1_identifier::constructed_bit);
    auto version = asn1_read_integer(version_buf);
    assert(version_buf.remaining() == 0);
    std::cout << "Version " << (version+1) << std::endl;
    assert(version == 2); // v3

    auto serial_number = asn1_read_integer(elem_buf);
    std::cout << "Serial number: 0x" << std::hex << serial_number << std::dec << std::endl;

    auto algo_id = asn1_read_algorithm_identifer(elem_buf);
    const asn1_object_id sha256WithRSAEncryption{1,2,840,113549,1,1,11};
    std::cout << "Algorithm: " << algo_id;
    std::cout << "  - Expecting " << sha256WithRSAEncryption << " (sha256WithRSAEncryption)" << std::endl;
    assert(algo_id == sha256WithRSAEncryption);

    std::cout << "Issuer:\n";
    parse_Name(elem_buf);

    auto validity_buf = asn1_expect_id(elem_buf, asn1_identifier::constructed_sequence);
    auto notbefore    = parse_UTCTime(validity_buf);
    auto notafter     = parse_UTCTime(validity_buf);
    assert(validity_buf.remaining() == 0);
    std::cout << "Validity: Between " << notbefore << " and " << notafter << std::endl;

    std::cout << "Subject:\n";
    parse_Name(elem_buf);

    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //    algorithm            AlgorithmIdentifier,
    //    subjectPublicKey     BIT STRING  }
    auto subject_public_key = parse_RSAPublicKey(elem_buf);
    std::cout << std::hex;
    std::cout << "Subject public key: n=0x" << subject_public_key.modolus << " e=0x" << subject_public_key.public_exponent << std::endl;
    std::cout << std::dec;

    while (elem_buf.remaining()) {
        auto id = read_asn1_identifier(elem_buf);
        auto len = read_asn1_length(elem_buf);
        if (id == (asn1_identifier::tagged(1) | asn1_identifier::constructed_bit)) {
            assert(version == 1 || version == 2); // Must be v2 or v3
            elem_buf.skip(len); // Skip issuerUniqueID
        } else if (id == (asn1_identifier::tagged(2) | asn1_identifier::constructed_bit)) {
            assert(version == 1 || version == 2); // Must be v2 or v3
            elem_buf.skip(len); // Skip subjectUniqueID
        } else if (id == (asn1_identifier::tagged(3) | asn1_identifier::constructed_bit)) {
            assert(version == 2); // Must be v3
            elem_buf.skip(len); // Skip extensions
        } else {
            std::ostringstream oss;
            oss << "Unknown tag found in " << __PRETTY_FUNCTION__ << ": " << id << " len = " << len;
            throw std::runtime_error(oss.str());
        }
    }
}

void parse_x509_v3(buffer_view& buf) // in ASN.1 DER encoding (X.690)
{
    auto elem_buf = asn1_expect_id(buf, asn1_identifier::constructed_sequence);
    auto cert_buf = asn1_expect_id(elem_buf, asn1_identifier::constructed_sequence);
    if (!cert_buf.remaining()) {
        throw std::runtime_error("Empty certificate in " + std::string(__PRETTY_FUNCTION__));
    }

    // Save certificate data for verification against the signature
    std::vector<uint8_t> tbsCertificate(cert_buf.remaining());
    cert_buf.get_many(&tbsCertificate[0], tbsCertificate.size());
    buffer_view cert_buf_view(&tbsCertificate[0], tbsCertificate.size());
    parse_TBSCertificate(cert_buf_view);

    auto sig_algo = info_from_algorithm_id(asn1_read_algorithm_identifer(elem_buf));
    std::cout << "Signature algorithm: " << sig_algo << std::endl;
    assert(sig_algo.algorithm_identifier() == x509_sha256WithRSAEncryption);
    auto sig_value = asn1_read_bit_string(elem_buf);
    std::cout << " " << sig_value.size() << " bits" << std::endl;
    std::cout << " " << sig_value << std::endl;
    assert(elem_buf.remaining() == 0);

    // The signatureValue field contains a digital signature computed upon
    // the ASN.1 DER encoded tbsCertificate.  The ASN.1 DER encoded
    // tbsCertificate is used as the input to the signature function.

    // TOOD: Check that sig_value == sha256WithRSAEncryption(tbsCertificate)
    // http://tools.ietf.org/html/rfc3447
}

std::vector<uint8_t> read_file(const std::string& filename)
{
    std::ifstream in(filename);
    if (!in || !in.is_open()) {
        throw std::runtime_error("Could not open " + filename);
    }
    in.seekg(0, std::ifstream::end);
    std::vector<uint8_t> buffer(in.tellg());
    in.seekg(0, std::ifstream::beg);
    in.read(reinterpret_cast<char*>(&buffer[0]), buffer.size());
    if (!in) {
        throw std::runtime_error("Error reading from " + filename);
    }
    return buffer;
}

int main()
{
    auto cert = read_file("server.crt");
    assert(cert.size());
    buffer_view cert_buf(&cert[0], cert.size());
    parse_x509_v3(cert_buf);
}
