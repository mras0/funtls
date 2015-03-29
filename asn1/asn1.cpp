#include "asn1.h"
#include <ostream>
#include <cassert>
#include <stdexcept>

#include <util/base_conversion.h>

namespace {

static int utc_time_get_digit(char d) {
    if (d < '0' || d > '9') throw std::runtime_error("Invalid digit found in UTC time: " + std::string(1, d));
    return d - '0';
}

static int utc_time_get_2digit_int(const char* src) {
    return 10 * utc_time_get_digit(src[0]) + utc_time_get_digit(src[1]);
}

static int utc_time_get_2digit_int_checked(const char* src, int min, int max, const char* name) {
    int n = utc_time_get_2digit_int(src);
    if (n < min) throw std::runtime_error(std::string(name) + " is too small " + std::to_string(n) + " < " + std::to_string(min));
    if (n > max) throw std::runtime_error(std::string(name) + " is too large " + std::to_string(n) + " > " + std::to_string(max));
    return n;
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

} // unnamed namespace

namespace funtls { namespace asn1 {

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

std::ostream& operator<<(std::ostream& os, const object_id& oid)
{
    assert(!oid.empty());
    for (unsigned i = 0; i < oid.size(); ++i) {
        if (i) os << ".";
        os << oid[i];
    }
    return os;
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
    if (s.length() < 11 || s.length() > 19) {
        throw std::runtime_error("Invalid length of UTCTime '" + s + "'");
    }
    const int year   = 2000 + utc_time_get_2digit_int(&s[0]);
    const int month  = utc_time_get_2digit_int_checked(&s[2], 1, 12, "month");
    const int date   = utc_time_get_2digit_int_checked(&s[4], 1, 31, "date");
    const int hour   = utc_time_get_2digit_int_checked(&s[6], 0, 23, "hour");
    const int minute = utc_time_get_2digit_int_checked(&s[8], 0, 59, "minute");
    int second = 0;
    std::string tz;
    if (isdigit(s[10])) {
        if (s.length() < 13) {
            throw std::runtime_error("Invalid length of UTCTime '" + s + "'");
        }
        second = utc_time_get_2digit_int_checked(&s[10], 0, 59, "second");
        tz = std::string(&s[12]);
    } else {
        tz = std::string(&s[10]);
    }
    // TODO: Check that the date is legal (e.g. no february 31th)
    // TODO: Check that the time zone is valid
    (void) year; (void) month; (void) date;
    (void) hour; (void) minute; (void) second;
    (void) tz;
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

der_encoded_value::der_encoded_value(const util::buffer_view& buffer, size_t content_offset, asn1::identifier id, size_t content_length)
    : buffer_(buffer)
    , content_offset_(content_offset)
    , id_(id)
    , length_(content_length)
{
}

std::ostream& operator<<(std::ostream& os, const der_encoded_value& t)
{
    uint8_t id = static_cast<uint8_t>(t.id());
    os << "id = 0x" << util::base16_encode(&id ,1) << " len = " << t.length();
    return os;
}

util::buffer_view der_encoded_value::content_view() const
{
    auto buf_copy = buffer_;
    buf_copy.skip(content_offset_);
    return buf_copy.get_slice(length_);
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

} } // namespace funtls::asn1
