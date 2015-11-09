#include <iostream>
#include <sstream>
#include <stdexcept>
#include <cassert>

#include <util/base_conversion.h>
#include <util/buffer.h>
#include <util/test.h>
#include <asn1/asn1.h>

using namespace funtls;

asn1::der_encoded_value value_from_bytes(const std::vector<uint8_t>& data)
{
    assert(data.size());
    util::buffer_view buf(&data[0], data.size());
    auto value = asn1::read_der_encoded_value(buf);
    FUNTLS_ASSERT_EQUAL(0, buf.remaining());
    return value;
}

std::vector<uint8_t> make_vec(asn1::identifier id, const std::vector<uint8_t>& data)
{
    assert(data.size() < 0x80);
    std::vector<uint8_t> res;
    res.push_back(static_cast<uint8_t>(id));
    res.push_back(static_cast<uint8_t>(data.size()));
    res.insert(res.end(), data.begin(), data.end());
    return res;
}

template<typename T>
T from_bytes(const std::vector<uint8_t>& d)
{
    const auto bytes = make_vec(T::id, d);
    return T{value_from_bytes(bytes)};
}

template<typename T>
T from_str(const std::string& s)
{
    return from_bytes<T>(std::vector<uint8_t>(s.begin(), s.end()));
}

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& v) {
    return os << util::base16_encode(v);
}

#include <int_util/int.h>

void test_asn1()
{
    using namespace util;
    using namespace asn1;

    std::vector<uint8_t> illegal_length{ static_cast<uint8_t>(identifier::integer), 4, 0 };
    FUNTLS_ASSERT_THROWS(value_from_bytes(illegal_length), std::runtime_error);

    //
    // NULL
    //

    const auto null_value_bytes = make_vec(identifier::null, {});
    auto null_value = value_from_bytes(null_value_bytes);
    FUNTLS_ASSERT_EQUAL(identifier::null, null_value.id());
    FUNTLS_ASSERT_EQUAL(2, null_value.complete_view().size());
    FUNTLS_ASSERT_EQUAL(0, null_value.content_view().size());

    //
    // BOOLEAN
    //
    {
        FUNTLS_ASSERT_EQUAL(from_bytes<boolean>({0x00}), false);
        FUNTLS_ASSERT_EQUAL(from_bytes<boolean>({0x01}), true);
        FUNTLS_ASSERT_EQUAL(from_bytes<boolean>({0x82}), true);
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x01, 0x01, 0x00}), serialized(boolean{false}));
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x01, 0x01, 0x01}), serialized(boolean{true}));
    }

    //
    // INTEGER
    //

    const auto int_value_1_bytes = make_vec(identifier::integer, {42});
    auto int_value_1 = value_from_bytes(int_value_1_bytes);
    FUNTLS_ASSERT_EQUAL(identifier::integer, int_value_1.id());
    FUNTLS_ASSERT_EQUAL(3, int_value_1.complete_view().size());
    FUNTLS_ASSERT_EQUAL(1, int_value_1.content_view().size());
    FUNTLS_ASSERT_EQUAL(42, int_value_1.content_view().get());
    auto int_value_1_ = integer{int_value_1};
    FUNTLS_ASSERT_EQUAL(1, int_value_1_.octet_count());
    FUNTLS_ASSERT_EQUAL(42, int_value_1_.octet(0));

    // TODO: Check illegal encodings
    // E.g. ints encoded with more than the needed bytes

    static const struct {
        int64_t int_val;
        std::vector<uint8_t> bytes;
    } int_test_cases[] = {
        { 0, { 0 } },
        { 60, { 60 } },
        { 127, { 0x7f } },
        { 128, { 0x00, 0x80 } },
        { 256, { 0x01, 0x00 } },
        //{ -128, { 0x80 } },
        //{ -129, { 0xFF, 0x7F } },
    };

    for (const auto& int_test_case : int_test_cases) {
        auto the_int = from_bytes<integer>(int_test_case.bytes);
        FUNTLS_ASSERT_EQUAL(int_test_case.bytes.size(), the_int.octet_count());
        for (size_t i = 0; i < int_test_case.bytes.size(); ++i) {
            FUNTLS_ASSERT_EQUAL(int_test_case.bytes[i], the_int.octet(i));
        }
        FUNTLS_ASSERT_EQUAL(int_test_case.int_val, the_int.as<int64_t>());
        FUNTLS_ASSERT_EQUAL(large_uint(int_test_case.int_val), the_int.as<large_uint>());
        if (int_test_case.bytes.size() == 1) {
            FUNTLS_ASSERT_EQUAL(static_cast<int8_t>(int_test_case.int_val), the_int.as<int8_t>());
        } else if (int_test_case.bytes.size() == 2) {
            FUNTLS_ASSERT_EQUAL(static_cast<int16_t>(int_test_case.int_val), the_int.as<int16_t>());
        } else {
            assert(false);
        }

        std::vector<uint8_t> int_serialized;
        std::vector<uint8_t> expected{2, static_cast<uint8_t>(int_test_case.bytes.size())};
        expected.insert(expected.end(), int_test_case.bytes.begin(), int_test_case.bytes.end());
        the_int.serialize(int_serialized);
        FUNTLS_ASSERT_EQUAL(expected, int_serialized);

    }
    auto large_int = from_bytes<integer>({0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff});
    FUNTLS_ASSERT_EQUAL(10, large_int.octet_count());
    FUNTLS_ASSERT_THROWS(large_int.as<int64_t>(), std::runtime_error);
    FUNTLS_ASSERT_EQUAL(large_uint("0x7fffffffffffffffffff"), large_int.as<large_uint>());

    //
    // OBJECT IDENTIFER
    //

    // { 1 2 840 113549 } RSA Data Security, Inc.
    auto oid_1 = from_bytes<object_id>({0x2a,0x86,0x48,0x86,0xf7,0x0d});
    FUNTLS_ASSERT_EQUAL(4, oid_1.size());
    FUNTLS_ASSERT_EQUAL(1, oid_1[0]);
    FUNTLS_ASSERT_EQUAL(2, oid_1[1]);
    FUNTLS_ASSERT_EQUAL(840, oid_1[2]);
    FUNTLS_ASSERT_EQUAL(113549, oid_1[3]);
    FUNTLS_ASSERT_EQUAL((asn1::object_id{1,2,840,113549}), oid_1);

    // Check serialization
    std::vector<uint8_t> oid_1_ser;
    oid_1.serialize(oid_1_ser);
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{6, 6, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d}), oid_1_ser);
    
    std::vector<uint8_t> oid_2_ser;
    const object_id id_sha1{1,3,14,3,2,26};
    id_sha1.serialize(oid_2_ser);
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a}), oid_2_ser);
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a}), serialized(id_sha1));

    // Check some illegal oids
    FUNTLS_ASSERT_THROWS(from_bytes<object_id>({}), std::runtime_error);
    FUNTLS_ASSERT_THROWS(from_bytes<object_id>({3*40}), std::runtime_error);
    FUNTLS_ASSERT_THROWS(from_bytes<object_id>({0x2a,0xff,0xff,0xff,0xff}), std::runtime_error);

    //
    // SEQUENCE
    //
    {
        std::vector<uint8_t> s_bytes = make_vec(identifier::constructed_sequence, make_vec(identifier::null, {}));
        auto s = sequence_view{value_from_bytes(s_bytes)};
        FUNTLS_ASSERT_EQUAL(true, s.has_next());
        auto x = s.next();
        FUNTLS_ASSERT_EQUAL(false, s.has_next());
        FUNTLS_ASSERT_EQUAL(identifier::null, x.id());
        FUNTLS_ASSERT_EQUAL(0, x.content_view().size());

        // Serialization
        auto ss = serialized_sequence(identifier::constructed_sequence, id_sha1, from_bytes<octet_string>({1,2,3}));
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x30, 0x0C, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x03, 0x01, 0x02, 0x03}), ss);
        auto ss2 = serialized_sequence(identifier::constructed_sequence, serialized_sequence(identifier::sequence, id_sha1), from_bytes<octet_string>({1,2,3}));
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x30, 0x0E, 0x10, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x03, 0x01, 0x02, 0x03}), ss2);
    }

    //
    // SET
    //
    {
        std::vector<uint8_t> s_bytes = make_vec(identifier::constructed_set, make_vec(identifier::integer, {22}));
        auto s = set_view{value_from_bytes(s_bytes)};
        FUNTLS_ASSERT_EQUAL(true, s.has_next());
        auto x = s.next();
        FUNTLS_ASSERT_EQUAL(false, s.has_next());
        FUNTLS_ASSERT_EQUAL(22, integer{x}.as<int8_t>());
    }

    //
    // strings
    //
    {
        FUNTLS_ASSERT_THROWS(from_bytes<utf8_string>({}), std::runtime_error);
        FUNTLS_ASSERT_EQUAL("A", from_bytes<utf8_string>({65}).as_string());
        FUNTLS_ASSERT_EQUAL("hello", from_bytes<utf8_string>({'h','e','l','l','o'}).as_string());
        auto vec = from_bytes<octet_string>({1,2,3}).as_vector();
        FUNTLS_ASSERT_EQUAL(3, vec.size());
        FUNTLS_ASSERT_EQUAL(1, vec[0]);
        FUNTLS_ASSERT_EQUAL(2, vec[1]);
        FUNTLS_ASSERT_EQUAL(3, vec[2]);

        // Check serialization
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x04, 0x02, 0x01, 0x02}), serialized(from_bytes<octet_string>({1,2})));
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x0C, 0x03, 'A', 'B', 'z'}), serialized(from_bytes<utf8_string>({'A','B','z'})));
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x0C, 0x03, 'A', 'B', 'z'}), serialized(any_string{from_bytes<utf8_string>({'A','B','z'})}));
    }

    //
    // BIT STRING
    //
    {
        FUNTLS_ASSERT_THROWS(from_bytes<bit_string>({}), std::runtime_error);
        FUNTLS_ASSERT_THROWS(from_bytes<bit_string>({0}), std::runtime_error);
        FUNTLS_ASSERT_THROWS(from_bytes<bit_string>({1}), std::runtime_error);
        FUNTLS_ASSERT_THROWS(from_bytes<bit_string>({9}), std::runtime_error);
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{(uint8_t)'A'}), from_bytes<bit_string>({0,65}).as_vector());
        FUNTLS_ASSERT_EQUAL(0, from_bytes<bit_string>({0,65}).excess_bits());
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0xF0}), from_bytes<bit_string>({0,0xF0}).repr());
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0xF0}), from_bytes<bit_string>({4,0xF0}).repr());
        FUNTLS_ASSERT_THROWS(from_bytes<bit_string>({5,0xF0}), std::runtime_error);
        FUNTLS_ASSERT_THROWS(from_bytes<bit_string>({5,0x01}), std::runtime_error);
        FUNTLS_ASSERT_EQUAL(6, from_bytes<bit_string>({0x06, 0x6e, 0x5d, 0xc0}).excess_bits());
        FUNTLS_ASSERT_EQUAL(18, from_bytes<bit_string>({0x06, 0x6e, 0x5d, 0xc0}).bit_count());
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x6e, 0x5d, 0xc0}), from_bytes<bit_string>({0x06, 0x6e, 0x5d, 0xc0}).repr());

        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x03, 0x03, 0x00, 0xff, 0x80}), serialized(bit_string{std::vector<uint8_t>{0xff,0x80}}));

        std::string s(500, 'x');
        std::vector<uint8_t> v(s.begin(), s.end());
        const auto x500str = serialized(bit_string{v});
        FUNTLS_ASSERT_EQUAL(505, x500str.size());
        FUNTLS_ASSERT_EQUAL(0x03, (unsigned)x500str[0]);
        FUNTLS_ASSERT_EQUAL(0x82, (unsigned)x500str[1]);
        FUNTLS_ASSERT_EQUAL(501/256, (unsigned)x500str[2]);
        FUNTLS_ASSERT_EQUAL(501%256, (unsigned)x500str[3]);
        FUNTLS_ASSERT_EQUAL(0x00, (unsigned)x500str[4]);
        for (int i = 0; i < 500; ++i) {
            FUNTLS_ASSERT_EQUAL('x', x500str[5+i]);
        }
        buffer_view reread{x500str.data(), x500str.size()};
        FUNTLS_ASSERT_EQUAL(v, bit_string{asn1::read_der_encoded_value(reread)}.as_vector());
    }

    //
    // UTC TIME
    //
    {
        // TODO: Improve testing of both valid dates and error cases
        const char* const bad_dates[] ={
            "",
            "151108227Z1",
            //"1511082227Z1", // Timezone isn't checked yet
            //"1502290000Z", // Dates aren't validated (No 29th of february in 2015)
        };
        for (auto d : bad_dates) {
            FUNTLS_ASSERT_THROWS_MESSAGE(from_str<utc_time>(d), std::runtime_error, d);
        }
        const char* const good_dates[] = {
            "1511082227Z",
            "151108222712Z",
            "1412011211+0500",
            "1412011211-0400",
            "141201121100-0015",
            "141201121100+0500"
        };
        for (auto d : good_dates) {
            FUNTLS_ASSERT_EQUAL(from_str<utc_time>(d).as_string(), d);
            const auto s = serialized(utc_time{d});
            const auto dlen = strlen(d);
            std::vector<uint8_t> expected_serialized{0x17, static_cast<uint8_t>(dlen)};
            expected_serialized.insert(expected_serialized.end(), d, d+dlen);
            FUNTLS_ASSERT_EQUAL(s, expected_serialized);
        }
    }
}

int main()
{
    try {
        test_asn1();
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}