#ifndef FUNTLS_ASN1_ASN1_H_INCLUDED
#define FUNTLS_ASN1_ASN1_H_INCLUDED

#include <stdint.h>
#include <iosfwd>
#include <vector>
#include <string>
#include <initializer_list>
#include <cassert>
#include <limits>
#include <type_traits>

#include <util/buffer.h>

namespace funtls { namespace asn1 {

//
// ASN.1 identifier
//

class identifier {
public:
    static constexpr uint8_t constructed_bit       = 0x20;
    static constexpr uint8_t context_specific_bits = 0x80;
    enum tag : uint8_t {
        boolean                 = 0x01,
        integer                 = 0x02,
        bit_string              = 0x03,
        octet_string            = 0x04,
        null                    = 0x05,
        object_id               = 0x06,
        utf8_string             = 0x0C,
        sequence                = 0x10,
        set                     = 0x11,
        printable_string        = 0x13,
        t61_string              = 0x14,
        ia5_string              = 0x16,
        utc_time                = 0x17,
        generalized_time        = 0x18,
        constructed_sequence    = sequence | constructed_bit,
        constructed_set         = set      | constructed_bit,

        // context specific
        context_specific_0  = context_specific_bits | 0,
        context_specific_1  = context_specific_bits | 1,
        context_specific_2  = context_specific_bits | 2,
        context_specific_3  = context_specific_bits | 3,
        context_specific_4  = context_specific_bits | 4,
        context_specific_5  = context_specific_bits | 5,
        context_specific_6  = context_specific_bits | 6,
        context_specific_7  = context_specific_bits | 7,
        context_specific_8  = context_specific_bits | 8,

        context_specific_constructed_0  = context_specific_bits | constructed_bit | 0,
        context_specific_constructed_1  = context_specific_bits | constructed_bit | 1,
        context_specific_constructed_2  = context_specific_bits | constructed_bit | 2,
        context_specific_constructed_3  = context_specific_bits | constructed_bit | 3,
    };

    constexpr identifier(tag value) : repr_(static_cast<uint8_t>(value)) {
    }

    explicit operator uint8_t() const {
        return repr_;
    }
private:
    uint8_t repr_;
};


inline bool operator==(const identifier& lhs, const identifier& rhs) {
    return static_cast<uint8_t>(lhs) == static_cast<uint8_t>(rhs);
}

inline bool operator!=(const identifier& lhs, const identifier& rhs) {
    return !(lhs == rhs);
}

identifier read_identifier(util::buffer_view& buffer);
std::ostream& operator<<(std::ostream& os, const identifier& ident);

//
// View of ASN.1 DER encoded value
//

class der_encoded_value {
public:
    asn1::identifier id() const { return id_; }

    util::buffer_view complete_view() const;
    util::buffer_view content_view() const;

private:
    der_encoded_value(const util::buffer_view& buffer, size_t content_offset, asn1::identifier id, size_t content_length);

    util::buffer_view  buffer_;
    size_t             content_offset_;
    asn1::identifier   id_;
    size_t             length_;

    friend der_encoded_value read_der_encoded_value(util::buffer_view& buffer);
};

der_encoded_value read_der_encoded_value(util::buffer_view& buffer);
std::ostream& operator<<(std::ostream& os, const der_encoded_value& t);

//
// Containter views
//

namespace detail {
void type_check(identifier expected, identifier actual);
}

template<identifier::tag tag>
class container_view {
public:
    static constexpr auto id = tag;

    explicit container_view(const der_encoded_value& repr)
        : buffer_(repr.content_view()) {
            detail::type_check(id, repr.id());
    }

    bool has_next() const {
        return buffer_.remaining() != 0;
    }

    der_encoded_value next() {
        return read_der_encoded_value(buffer_);
    }

private:
    util::buffer_view buffer_;
};

using sequence_view = container_view<identifier::constructed_sequence>;
using set_view = container_view<identifier::constructed_set>;

//
// ASN.1 BOOLEAN (tag = 0x01)
//
class boolean {
public:
    static constexpr auto id = identifier::boolean;

    explicit boolean(const der_encoded_value& repr);
    explicit boolean(bool b) : repr_(b) {
    }

    operator bool() const {
        return repr_ != 0;
    }

    uint8_t repr() const {
        return repr_;
    }

    void serialize(std::vector<uint8_t>& buf) const;

private:
    uint8_t repr_;
};

//
// ASN.1 INTEGER (tag = 0x02)
//
class integer {
public:
    static constexpr auto id = identifier::integer;

    template<typename IntType>
    explicit integer(IntType n) {
        assert(n >= 0);
        if (n == 0) {
            repr_.push_back(0);
            return;
        }

        std::vector<uint8_t> le_bytes;
        while (n != 0) {
            le_bytes.push_back(static_cast<uint8_t>(n));
            n >>= 8;
        }
        assert(!le_bytes.empty());
        // Must have zero byte if the most siginificant bit is set
        if (le_bytes.back() & 0x80) {
            le_bytes.push_back(0);
        }
        repr_ = std::vector<uint8_t>(le_bytes.crbegin(), le_bytes.crend());
    }

    explicit integer(const der_encoded_value& repr);

    // Would have liked to do this as an explicit conversion operator
    // but I couldn't get G++ 4.8.2 / boost mulitprecision 1.57.0 to play ball
    template<typename IntType>
    IntType as() const {
        assert(octet_count() > 0);
        check<IntType>(octet_count());
        IntType res = static_cast<int8_t>(octet(0));
        if (sizeof(IntType) > 1) {
            for (size_t i = 1; i < octet_count(); ++i) {
                res <<= 8;
                res |= octet(i);
            }
        }
        return res;
    }

    size_t octet_count() const {
        return repr_.size();
    }

    uint8_t octet(size_t index) const {
        assert(index < octet_count());
        return repr_[index];
    }

    std::vector<uint8_t> as_vector() const {
        return repr_;
    }

    void serialize(std::vector<uint8_t>& buf) const;

    static integer from_bytes(const std::vector<uint8_t>& repr) {
        return integer{repr};
    }

private:
    explicit integer(const std::vector<uint8_t>& repr) : repr_(repr) {
    }

    std::vector<uint8_t> repr_;


    //
    // Attemp to catch boost::multiprecision types. Only really tested with cpp_int
    //

    template<typename IntType>
    static void check(size_t octet_count, typename std::enable_if<std::numeric_limits<IntType>::is_bounded, IntType>::type* = 0) {
        static_assert(std::numeric_limits<IntType>::is_integer, "Can only cast ASN.1 integer to an integer type");
        do_check_size(sizeof(IntType), octet_count);
    }

    template<typename IntType>
    static void check(size_t, typename std::enable_if<!std::numeric_limits<IntType>::is_bounded, IntType>::type* = 0) {
    }

    static void do_check_size(size_t int_type_size, size_t octet_count);
};

//
// ASN.1 BIT STRING (tag = 0x03)
//
class bit_string {
public:
    static constexpr auto id = identifier::bit_string;

    explicit bit_string(const std::vector<uint8_t>& repr, uint8_t excess_bits = 0) : repr_(repr), excess_bits_(excess_bits) {
        assert(excess_bits_ < 8);
        assert(!repr.empty());
    }
    explicit bit_string(const der_encoded_value& repr);

    uint8_t excess_bits() const {
        return excess_bits_;
    }

    size_t bit_count() const {
        assert(excess_bits_ < 8);
        assert(repr_.size() >= 1);
        return repr_.size() * 8 - excess_bits_;
    }

    const std::vector<uint8_t>& as_vector() const;

    const std::vector<uint8_t>& repr() const {
        return repr_;
    }

    void serialize(std::vector<uint8_t>& buf) const;

private:
    std::vector<uint8_t> repr_;
    uint8_t              excess_bits_;
};

//
// ASN.1 OBJECT IDENTIFIER (tag = 0x06)
//

class object_id {
public:
    static constexpr auto id = identifier::object_id;

    explicit object_id(const der_encoded_value& repr);

    explicit object_id(const std::vector<uint32_t>& components) : components_(components) {
        assert(!components_.empty());
        assert(components_[0] == 0 || components_[0] == 1 || components_[0] == 2);
    }

    explicit object_id(std::initializer_list<uint32_t> components) : components_(components) {
        assert(!components_.empty());
        assert(components_[0] == 0 || components_[0] == 1 || components_[0] == 2);
    }

    bool empty() const {
        return components_.empty();
    }

    size_t size() const {
        return components_.size();
    }

    uint32_t operator[](size_t index) const {
        assert(index < size());
        return components_[index];
    }

    bool operator<(const object_id& rhs) const {
        return components_ < rhs.components_;
    }

    bool operator==(const object_id& rhs) const {
        return components_ == rhs.components_;
    }

    bool operator!=(const object_id& rhs) const {
        return !(*this == rhs);
    }

    std::string as_string() const;

    void serialize(std::vector<uint8_t>& buf) const;

private:
    std::vector<uint32_t> components_;
};

std::ostream& operator<<(std::ostream& os, const object_id& oid);

//
// ASN.1 UTCTime (tag = 0x17)
//

class utc_time {
public:
    static constexpr auto id = identifier::utc_time;

    explicit utc_time(const der_encoded_value& repr);

    explicit utc_time(const std::string& s) : repr_(s) {
        validate(repr_);
    }

    std::string as_string() const {
        return repr_;
    }

    void serialize(std::vector<uint8_t>& buf) const;
private:
    std::string repr_;

    static void validate(const std::string& s);
};

std::ostream& operator<<(std::ostream& os, const utc_time& t);

//
// ASN.1 string types
//

class raw_string {
public:
    std::string as_string() const {
        return repr_;
    }

    std::vector<uint8_t> as_vector() const {
        assert(!repr_.empty());
        return {repr_.data(), repr_.data()+repr_.length()};
    }

protected:
    explicit raw_string(const std::string& repr)
        : repr_(repr) {
    }

    void do_serialize(identifier::tag id, std::vector<uint8_t>& buf) const;

private:
    std::string repr_;
};

std::ostream& operator<<(std::ostream& os, const raw_string& s);

namespace detail {
std::string read_string(identifier id, const der_encoded_value& repr);
} // namespace detail

template<identifier::tag tag>
class string_base : public raw_string {
public:
    static constexpr auto id = tag;

    explicit string_base(const der_encoded_value& repr)
        : raw_string(detail::read_string(id, repr)) {
    }

    explicit string_base(const std::string& repr)
        : raw_string(repr) {
    }

    void serialize(std::vector<uint8_t>& buf) const {
        do_serialize(tag, buf);
    }
};

class any_string : public raw_string {
public:
    explicit any_string(const der_encoded_value& repr)
        : raw_string(detail::read_string(repr.id(), repr))
        , id_(repr.id()) {
    }

    template<identifier::tag tag>
    /*implicit*/ any_string(const string_base<tag>& s)
        : raw_string(s)
        , id_(tag) {
    }

    identifier id() const {
        return id_;
    }

    void serialize(std::vector<uint8_t>& buf) const {
        do_serialize(static_cast<identifier::tag>(static_cast<uint8_t>(id_)), buf);
    }
private:
    identifier id_;
};

inline bool operator==(const any_string& lhs, const any_string& rhs) {
    return lhs.id() == rhs.id() && lhs.as_string() == rhs.as_string();
}

inline bool operator!=(const any_string& lhs, const any_string& rhs) {
    return !(lhs == rhs);
}

class octet_string : public string_base<identifier::octet_string> {
public:
    explicit octet_string(const der_encoded_value& repr)
        : string_base(repr) {
    }
    explicit octet_string(const std::vector<uint8_t>& repr)
        : string_base(std::string(repr.begin(), repr.end())) {
    }
};
using utf8_string = string_base<identifier::utf8_string>;
using printable_string = string_base<identifier::printable_string>;
using t61_string = string_base<identifier::t61_string>;
using ia5_string = string_base<identifier::ia5_string>;

namespace detail {

inline void serialize(std::vector<uint8_t>& buf, const std::vector<uint8_t>& buf2)
{
    buf.insert(buf.end(), buf2.begin(), buf2.end());
}

template<typename Obj>
inline void serialize(std::vector<uint8_t>& buf, const Obj& o)
{
    o.serialize(buf);
}

inline void serialize_all(std::vector<uint8_t>&)
{
}

template<typename Obj, typename... Objs>
inline void serialize_all(std::vector<uint8_t>& buf, const Obj& obj, const Objs&... objs)
{
    serialize(buf, obj);
    serialize_all(buf, objs...);
}

void fixup_size(std::vector<uint8_t>& buf, std::vector<uint8_t>::iterator size_byte, size_t size);

} // namespace detail

template<typename... Objs>
inline void serialize_sequence(std::vector<uint8_t>& buf, identifier id, const Objs&... objs) {

    buf.push_back(static_cast<uint8_t>(id));
    buf.push_back(0); // size, expand later on
    const auto content_begin_index = buf.size();
    detail::serialize_all(buf, objs...);
    const auto content_size = buf.size() - content_begin_index;
    if (content_size < 0x80) {
        buf[content_begin_index-1] = static_cast<uint8_t>(content_size);
    } else {
        detail::fixup_size(buf, buf.begin() + (content_begin_index - 1), content_size);
    }
}

template<typename Obj>
std::vector<uint8_t> serialized(const Obj& o) {
    std::vector<uint8_t> buf;
    detail::serialize(buf, o);
    return buf;
}

template<typename... Objs>
inline std::vector<uint8_t> serialized_sequence(identifier id, const Objs&... objs) {
    std::vector<uint8_t> buf;
    serialize_sequence(buf, id, objs...);
    return buf;
}



} } // namespace funtls::asn1

#endif
