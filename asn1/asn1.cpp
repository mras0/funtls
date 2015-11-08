#include "asn1.h"
#include <ostream>
#include <cassert>
#include <sstream>
#include <stdexcept>

#include <util/base_conversion.h>
#include <util/test.h>

#define FUNTLS_CHECK_ID(actual_id) FUNTLS_CHECK_BINARY(this->id, ==, actual_id, "Unexpected ASN.1 indentifer")

namespace {

template<typename C>
void serialize_helper(std::vector<uint8_t>& buf, funtls::asn1::identifier id, const C& data)
{
    static_assert(sizeof(*data.begin()) == 1, "Invalid container");
    buf.push_back(static_cast<uint8_t>(id));
    if (data.size() < 0x80) {
        buf.push_back(static_cast<uint8_t>(data.size()));
    } else {
        FUNTLS_CHECK_FAILURE("Not implemented");
    }
    buf.insert(buf.end(), data.begin(), data.end());
}

static int utc_time_get_digit(char d) {
    if (d < '0' || d > '9') throw std::runtime_error("Invalid digit found in UTC time: " + std::string(1, d));
    return d - '0';
}

static int utc_time_get_2digit_int(const char* src) {
    return 10 * utc_time_get_digit(src[0]) + utc_time_get_digit(src[1]);
}

size_t read_content_length(funtls::util::buffer_view& buf)
{
    const uint8_t first_size_byte = buf.get();
    if (first_size_byte & 0x80) {
        const uint8_t length_octets = first_size_byte & 0x7f;
        if (length_octets > sizeof(size_t)) {
            // This also handles the case where length_octets = 0x7f
            // which is always illegal
            throw std::runtime_error("Invalid length octet count " + funtls::util::base16_encode(&length_octets, 1));
        }
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

std::vector<uint8_t> copy_of(const funtls::util::buffer_view& buf)
{
    if (buf.remaining() == 0) return {};
    auto buf_copy = buf;
    std::vector<uint8_t> res(buf_copy.remaining());
    buf_copy.read(&res[0], res.size());
    assert(buf_copy.remaining() == 0);
    return res;
}

} // unnamed namespace

namespace funtls { namespace asn1 {

namespace detail {
void type_check(identifier expected, identifier actual)
{
    FUNTLS_CHECK_BINARY(expected, ==, actual, "Invalid container tag");
}

std::string read_string(identifier id, const der_encoded_value& repr)
{
    type_check(id, repr.id());
    auto buf = repr.content_view();
    FUNTLS_CHECK_BINARY(buf.remaining(), >=, 1, "Empty string");
    std::string s(buf.remaining(), '\0');
    buf.read(&s[0], buf.remaining());
    // TODO: Check that the string is valid
    return s;
}

} // namespace detail

identifier read_identifier(util::buffer_view& buffer)
{
    const uint8_t id = buffer.get();
    // If the identifier is not universal, its tag may be a number that is greater than 30. 
    // In that case, the tag does not fit in the 5-bit tag field, and must be encoded in subsequent octets. 
    // The value 11111 is reserved for identifying such encodings.
    if ((id&0x1f) == 31) {
        throw std::runtime_error("Unsupported ASN.1 identifier 0x" + util::base16_encode(&id, 1));
    }
    return asn1::identifier{static_cast<asn1::identifier::tag>(id)};
}

std::ostream& operator<<(std::ostream& os, const identifier& ident)
{
    uint8_t id = static_cast<uint8_t>(ident);
    uint8_t clazz = (id >> 6) & 3;
    bool    constructed = (id & identifier::constructed_bit) != 0;
    uint8_t tag = id & 0x1f;
    static const char* const clazz_name[] = { "universal", "application", "context-specific", "private" };
    os << "<identifier 0x" <<  funtls::util::base16_encode(&id, 1);
    os << " " << clazz_name[clazz];
    os << " " << (constructed ? "constructed" : "primitive");
    os << " " << static_cast<unsigned>(tag);
    os << ">";
    return os;
}

der_encoded_value::der_encoded_value(const util::buffer_view& buffer, size_t content_offset, asn1::identifier id, size_t content_length)
    : buffer_(buffer)
    , content_offset_(content_offset)
    , id_(id)
    , length_(content_length)
{
}

util::buffer_view der_encoded_value::complete_view() const
{
    auto buf_copy = buffer_;
    return buf_copy;
}

util::buffer_view der_encoded_value::content_view() const
{
    auto buf_copy = buffer_;
    buf_copy.skip(content_offset_);
    return buf_copy.get_slice(length_);
}

std::ostream& operator<<(std::ostream& os, const der_encoded_value& t)
{
    uint8_t id = static_cast<uint8_t>(t.id());
    os << "id = 0x" << util::base16_encode(&id ,1) << " len = " << t.content_view().size();
    return os;
}


der_encoded_value read_der_encoded_value(util::buffer_view& buffer)
{
    auto orig_buf = buffer;
    const auto id  = read_identifier(buffer);
    const auto len = read_content_length(buffer);
    const auto offset = buffer.index() - orig_buf.index();
    buffer.skip(len);
    return {orig_buf.get_slice(offset + len), offset, id, len};
}

boolean::boolean(const der_encoded_value& repr)
{
    FUNTLS_CHECK_ID(repr.id());
    auto buf = repr.content_view();
    FUNTLS_CHECK_BINARY(buf.remaining(), ==, 1, "Invalid boolean length encountered");
    repr_ = buf.get();
}

integer::integer(const der_encoded_value& repr)
{
    FUNTLS_CHECK_ID(repr.id());
    auto int_buf = repr.content_view();
    FUNTLS_CHECK_BINARY(int_buf.remaining(), >=, 1, "Empty integer encountered");

    repr_ = copy_of(repr.content_view());
}

void integer::do_check_size(size_t int_type_size, size_t octet_count)
{
    FUNTLS_CHECK_BINARY(int_type_size, >=, octet_count, "Integer out of " + std::to_string(int_type_size*8) + "-bit integer range");
}

void integer::serialize(std::vector<uint8_t>& buf) const
{
    serialize_helper(buf, id, repr_);
}

bit_string::bit_string(const der_encoded_value& repr)
{
    FUNTLS_CHECK_ID(repr.id());
    auto buf = repr.content_view();
    FUNTLS_CHECK_BINARY(buf.remaining(), >=, 2, "Empty bit string");
    excess_bits_ = buf.get();
    FUNTLS_CHECK_BINARY(unsigned(excess_bits_), <, 8, "Unsupported bit count");
    repr_.resize(buf.remaining());
    buf.read(&repr_[0], buf.remaining());
    // Check that repr_.back() doesn't have illegal bits set
    if (excess_bits_) {
        FUNTLS_CHECK_BINARY(repr_.back() & ((1<<excess_bits_)-1), ==, 0, "Invalid padding in bit_string");
    }
}

const std::vector<uint8_t>& bit_string::as_vector() const
{
    FUNTLS_CHECK_BINARY(excess_bits_, ==, 0, "Bit string has excess bits");
    return repr_;
}

void bit_string::serialize(std::vector<uint8_t>& buf) const
{
    std::vector<uint8_t> temp = repr_;
    temp.insert(temp.begin(), excess_bits_);
    serialize_helper(buf, id, temp);
}

object_id::object_id(const der_encoded_value& repr)
{
    FUNTLS_CHECK_ID(repr.id());
    auto oid_buf = repr.content_view();

    FUNTLS_CHECK_BINARY(oid_buf.remaining(), >=, 1, "Invalid object identifier size");
    FUNTLS_CHECK_BINARY(oid_buf.remaining(), <, 20, "Invalid object identifier size");

    // The first octet has value 40 * value1 + value2.
    // (This is unambiguous, since value1 is limited to values 0, 1, and 2; value2 is limited to the 
    // range 0 to 39 when value1 is 0 or 1; and, according to X.208, n is always at least 2.)
    const uint8_t first = oid_buf.get();
    components_.push_back(first/40);
    components_.push_back(first%40);

    FUNTLS_CHECK_BINARY(components_[0], <=, 2, "First component of object identifier not 0, 1 or 2");

    // The following octets, if any, encode value3, ..., valuen. Each value is encoded base 128, 
    // most significant digit first, with as few digits as possible, and the most significant bit 
    // of each octet except the last in the value's encoding set to "1."*
    while (oid_buf.remaining()) {
        uint32_t value = 0;
        uint8_t read_byte = 0;
        do {
            // OIDs must be less than 2^28, so if the value before shifting by 7 is >= 2^21
            // it is about to become out of range
            FUNTLS_CHECK_BINARY(value, <, (1<<21), "Object identifier component value out of range");
            read_byte = oid_buf.get();
            value <<= 7;
            value |= read_byte & 0x7f;
        } while (read_byte & 0x80);
        components_.push_back(value);
    }

    assert(oid_buf.remaining() == 0);
}

void object_id::serialize(std::vector<uint8_t>& buf) const
{
    buf.push_back(static_cast<uint8_t>(id));
    const auto size_index = buf.size();
    buf.push_back(0); // size, will be set later
    buf.push_back(static_cast<uint8_t>(components_[0] * 40 + components_[1]));
    for (size_t i = 2; i < components_.size(); ++i) {
        auto n = components_[i];
        if (n >= 1<<21) {
            buf.push_back(static_cast<uint8_t>(0x80 | ((n >> 21) & 0x7f)));
            buf.push_back(static_cast<uint8_t>(0x80 | ((n >> 14) & 0x7f)));
            buf.push_back(static_cast<uint8_t>(0x80 | ((n >> 7) & 0x7f)));
            buf.push_back(static_cast<uint8_t>(n & 0x7f));
        } else if (n >= 1<<14) {
            buf.push_back(static_cast<uint8_t>(0x80 | ((n >> 14) & 0x7f)));
            buf.push_back(static_cast<uint8_t>(0x80 | ((n >> 7) & 0x7f)));
            buf.push_back(static_cast<uint8_t>(n & 0x7f));
        } else if (n >= 1<<7) {
            buf.push_back(static_cast<uint8_t>(0x80 | ((n >> 7) & 0x7f)));
            buf.push_back(static_cast<uint8_t>(n & 0x7f));
        } else {
            buf.push_back(static_cast<uint8_t>(n));
        }
    }
    const auto num_bytes = buf.size() - size_index - 1;
    assert(num_bytes < 20);
    buf[size_index] = static_cast<uint8_t>(num_bytes);
}

std::string object_id::as_string() const
{
    std::ostringstream oss;
    oss << *this;
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const object_id& oid)
{
    assert(!oid.empty());
    for (unsigned i = 0; i < oid.size(); ++i) {
        if (i) os << ".";
        os << oid[i];
    }
    return os;
}

utc_time::utc_time(const der_encoded_value& repr) {
    auto utc_time_buf = repr.content_view();
    if (repr.id() == identifier::tag::generalized_time) {
        // HACK:
        std::string s(utc_time_buf.remaining(), '\0');
        utc_time_buf.read(&s[0], s.length());
        repr_ = "HACK in " + std::string(__FILE__) + ":" + std::to_string(__LINE__) + s;
        return;
    }
    FUNTLS_CHECK_ID(repr.id());

    FUNTLS_CHECK_BINARY(utc_time_buf.remaining(), >=, 11, "Not enough data for UTCTime");

    std::string s(utc_time_buf.remaining(), '\0');
    utc_time_buf.read(&s[0], s.length());
    validate(s);

    repr_ = s;
}

void utc_time::validate(const std::string& s)
{
    // Valid formats:
    // 0123456789012345678
    // YYMMDDhhmmZ
    // YYMMDDhhmm+hh'mm'
    // YYMMDDhhmm-hh'mm'
    // YYMMDDhhmmssZ
    // YYMMDDhhmmss+hh'mm'
    // YYMMDDhhmmss-hh'mm'
    FUNTLS_CHECK_BINARY(s.length(), >=, 11, "Invalid length oF UTCTime " + s);
    FUNTLS_CHECK_BINARY(s.length(), <=, 19, "Invalid length oF UTCTime " + s);
    const int year   = 2000 + utc_time_get_2digit_int(&s[0]);
    const int month  = utc_time_get_2digit_int(&s[2]);
    FUNTLS_CHECK_BINARY(month, >=, 1, "Invalid month in UTCTime " + s);
    FUNTLS_CHECK_BINARY(month, <=, 12, "Invalid month in UTCTime " + s);
    const int date   = utc_time_get_2digit_int(&s[4]);
    FUNTLS_CHECK_BINARY(date, >=, 1, "Invalid date in UTCTime " + s);
    FUNTLS_CHECK_BINARY(date, <=, 31, "Invalid date in UTCTime " + s);
    const int hour   = utc_time_get_2digit_int(&s[6]);
    FUNTLS_CHECK_BINARY(hour, >=, 0, "Invalid hour in UTCTime " + s);
    FUNTLS_CHECK_BINARY(hour, <=, 23, "Invalid hour in UTCTime " + s);
    const int minute = utc_time_get_2digit_int(&s[8]);
    FUNTLS_CHECK_BINARY(minute, >=, 0, "Invalid minute in UTCTime " + s);
    FUNTLS_CHECK_BINARY(minute, <=, 59, "Invalid minute in UTCTime " + s);
    int second = 0;
    std::string tz;
    if (isdigit(s[10])) {
        FUNTLS_CHECK_BINARY(s.length(), >=, 13, "Invalid length oF UTCTime " + s);
        second = utc_time_get_2digit_int(&s[10]);
        FUNTLS_CHECK_BINARY(second, >=, 0, "Invalid second in UTCTime " + s);
        FUNTLS_CHECK_BINARY(second, <=, 59, "Invalid second in UTCTime " + s);
        tz = std::string(&s[12]);
    } else {
        tz = std::string(&s[10]);
    }
    // TODO: Check that the date is legal (e.g. no february 31th)
    (void) year;
    // TODO: Check that the time zone is valid
    (void) tz;
}

void utc_time::serialize(std::vector<uint8_t>& buf) const
{
    serialize_helper(buf, id, repr_);
}

std::ostream& operator<<(std::ostream& os, const utc_time& t) {
#if 0
        auto fill = os.fill();
        os.fill('0');
        os << std::setw(4) << t.year << "-" << std::setw(2) << t.month << "-" << std::setw(2) << t.date << " ";
        os << std::setw(2) << t.hour << ":" << std::setw(2) << t.minute << ":" << std::setw(2) << t.second << t.tz;
        os.fill(fill);
        return os;
#endif
    os << t.as_string();
    return os;
}

std::ostream& operator<<(std::ostream& os, const raw_string& s)
{
    os << s.as_string();
    return os;
}

void raw_string::do_serialize(identifier::tag id, std::vector<uint8_t>& buf) const
{
    serialize_helper(buf, id, repr_);
}

} } // namespace funtls::asn1
