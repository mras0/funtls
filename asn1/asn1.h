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
    static constexpr uint8_t constructed_bit = 0x20;
    enum tag : uint8_t {
        integer                 = 0x02,
        bit_string              = 0x03,
        octet_string            = 0x04,
        null                    = 0x05,
        object_id               = 0x06,
        utf8_string             = 0x0C,
        sequence                = 0x10,
        set                     = 0x11,
        printable_string        = 0x13,
        utc_time                = 0x17,
        constructed_sequence    = sequence | constructed_bit,
        constructed_set         = set      | constructed_bit,

        // context specific
        context_specific_tag_0  = 0 | (2<<6) | constructed_bit, 
        context_specific_tag_1  = 1 | (2<<6) | constructed_bit, // context specific
        context_specific_tag_2  = 2 | (2<<6) | constructed_bit, // context specific
        context_specific_tag_3  = 3 | (2<<6) | constructed_bit, // context specific
    };

    identifier(tag value) : repr_(static_cast<uint8_t>(value)) {
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
// ASN.1 DER encoded value
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
// ASN.1 INTEGER (tag = 0x02)
//
class integer {
public:
    static constexpr auto id = identifier::integer;

    integer(const der_encoded_value& repr);

    // Would have liked to do this as an explicit conversion operator
    // but I couldn't get G++ 4.8.2 / boost mulitprecision 1.57.0 to play ball
    template<typename IntType>
    IntType as() const {
        assert(octet_count() > 0);
        check<IntType>(octet_count());
        IntType res = static_cast<int8_t>(octet(0));
        for (size_t i = 1; i < octet_count(); ++i) {
            res <<= 8;
            res |= octet(i);
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
private:
    std::vector<uint8_t> repr_;

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
// ASN.1 OBJECT IDENTIFIER (tag = 0x06)
//

class object_id {
public:
    static constexpr auto id = identifier::object_id;

    object_id(const der_encoded_value& repr);

    object_id(const std::vector<uint32_t>& components) : components_(components) {
        assert(!components_.empty());
        assert(components_[0] == 0 || components_[0] == 1 || components_[0] == 2);
    }

    object_id(std::initializer_list<uint32_t> components) : components_(components) {
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

    bool operator==(const object_id& rhs) const {
        return components_ == rhs.components_;
    }

    bool operator!=(const object_id& rhs) const {
        return !(*this == rhs);
    }

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

    utc_time(const der_encoded_value& repr);

    utc_time(const std::string& s) : repr_(s) {
        validate(repr_);
    }

    std::string as_string() const {
        return repr_;
    }
private:
    std::string repr_;

    static void validate(const std::string& s);
};

std::ostream& operator<<(std::ostream& os, const utc_time& t);

} } // namespace funtls::asn1

#endif
