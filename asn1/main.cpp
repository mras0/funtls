#include <iostream>
#include <fstream>
#include <vector>
#include <string>
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
        integer   = 0x02,
        object_id = 0x06,
        sequence  = 0x10,
        set       = 0x11,
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

uint64_t asn1_get_unsigned(buffer_view& buf, size_t len)
{
    uint64_t n = 0;
    for (unsigned i = 0; i < len; ++i) {
        n <<= 8;
        n |= buf.get();
    }
    return n;
}

size_t read_asn1_length(buffer_view& buf)
{
    const uint8_t first_size_byte = buf.get();
    if (first_size_byte & 0x80) {
        const uint8_t length_octets = first_size_byte & 0x7f;
        if (length_octets == 0x7f) throw std::runtime_error("Illegal length octet");
        if (length_octets > sizeof(size_t)) throw std::runtime_error("Unsupported length octet count " + std::to_string(length_octets));
        size_t sz = asn1_get_unsigned(buf, length_octets);
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
    std::cout << "Read integer: " << val << std::endl;
    return val;
}

void put_oid(std::ostream& os, const std::vector<uint64_t>& oid)
{
    assert(!oid.empty());
    os << oid[0];
    for (unsigned i = 1; i < oid.size(); ++i) {
        os << "." << oid[i];
    }
}

std::vector<uint64_t> asn1_read_object_id(buffer_view& buf)
{
    auto oid_buf = asn1_expect_id(buf, asn1_identifier::object_id);
    if (oid_buf.size() < 1 || oid_buf.size() > 20) { // What are common sizes?
        throw std::runtime_error("Invalid oid size " + std::to_string(oid_buf.size()) + " in " + __PRETTY_FUNCTION__);
    }
    const uint8_t first = oid_buf.get();
    std::vector<uint64_t> res;
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
        uint64_t value = 0;
        uint8_t read_byte = 0;
        do {
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


void parse_TBSCertificate(buffer_view& buf)
{
    auto elem_buf = asn1_expect_id(buf, asn1_identifier::constructed_sequence);

    auto version_buf = asn1_expect_id(elem_buf, asn1_identifier::tagged(0) | asn1_identifier::constructed_bit);
    auto ver = asn1_read_integer(version_buf);
    assert(version_buf.remaining() == 0);
    std::cout << "Version " << (ver+1) << std::endl;
    assert(ver == 2); // v3

    auto serial_number = asn1_read_integer(elem_buf);
    std::cout << "Serial number: 0x" << std::hex << serial_number << std::dec << std::endl;

    auto algo_buf = asn1_expect_id(elem_buf, asn1_identifier::constructed_sequence);
    auto algo_id = asn1_read_object_id(algo_buf); // algorithm OBJECT IDENTIFIER,
    //Ignore - parameters  ANY DEFINED BY algorithm OPTIONAL  }
    std::cout << "Algorithm: "; put_oid(std::cout, algo_id); std::cout << std::endl;
    std::cout << "  - Expecting 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)" << std::endl;
    assert(algo_id == std::vector<uint64_t>({1,2,840,113549,1,1,11}));

    // Name ::= CHOICE { RDNSequence }
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName 
    // RelativeDistinguishedName ::= SET OF AttributeValueAssertion
    // AttributeValueAssertion ::= SEQUENCE { AttributeType, AttributeValue }
    // AttributeType ::= OBJECT IDENTIFIER
    // AttributeValue ::= ANY
    auto issuer_name_buf = asn1_expect_id(elem_buf, asn1_identifier::constructed_sequence); // RDNSequence
    while (issuer_name_buf.remaining()) {
        auto rdn_buf = asn1_expect_id(issuer_name_buf, asn1_identifier::constructed_set);
        while (rdn_buf.remaining()) {
            auto av_pair_buf = asn1_expect_id(rdn_buf, asn1_identifier::constructed_sequence);
            auto attribute_type = asn1_read_object_id(av_pair_buf);
            std::cout << "Attribute: "; put_oid(std::cout, attribute_type); std::cout << std::endl;
            auto id = read_asn1_identifier(av_pair_buf);
            auto len = read_asn1_length(av_pair_buf);
            std::cout << "Skipping value:  len=" << std::setw(4) << len << " " << id << std::endl;
            // 12 and 19 are UTF8String and PrintableString  respectively
            // must be some kind of string type
            av_pair_buf.skip(len);
            assert(av_pair_buf.remaining() == 0);
        }
        std::cout << std::endl; // end of RelativeDistinguishedName
    }

    print_all(elem_buf, "TDS");
}

void parse_x509_v3(buffer_view& buf) // in ASN.1 DER encoding (X.690)
{
    auto elem_buf = asn1_expect_id(buf, asn1_identifier::constructed_sequence);
    parse_TBSCertificate(elem_buf);
    print_all(elem_buf, "CERT");
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
