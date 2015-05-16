#include <iostream>
#include <string>
#include <bigint/bigint.h>
#include <util/base_conversion.h>
#include <util/test.h>

// Testplan:
//  - hex output and initialization (bootstrap)
//  - hex input (larger test cases can be built)
//  - equality
//  - addition
// TODO: mul, mod, pow(m), modular inverse
// etc. (neg, sub, arbitrary precesion?)

using namespace funtls;

static const struct {
    const char* expected;
    uint64_t    val;
} u64_test_cases[] = {
    {"0"                 , UINT64_C(0)                    },
    {"2A"                , UINT64_C(42)                   },
    {"100"               , UINT64_C(256)                  },
    {"29A"               , UINT64_C(666)                  },
    {"539"               , UINT64_C(1337)                 },
    {"7FFF"              , UINT64_C(32767)                },
    {"123456789ABCDEF"   , UINT64_C(81985529216486895)    },
    {"FFFFFFFFFFFFFFFF"  , UINT64_C(18446744073709551615) },
    {"AA00BB00CC00DD00"  , UINT64_C(0xAA00BB00CC00DD00)   },
    {"AA00BB00CC00DD"    , UINT64_C(0xAA00BB00CC00DD)     },
    {"A0AB00BC00C0DD00"  , UINT64_C(0xA0AB00BC00C0DD00)    },
    {"10230421723043"    , UINT64_C(0x10230421723043)     },
};
static const struct {
    std::string          expected;
    std::vector<uint8_t> bytes;
} be_bytes_test_cases[] = {
    { "0", {0x00} },
    { "2A", {0x2A} },
    { "FE", {0XFE} },
    { "FEDE", {0XFE,0XDE} },
    { "FEDEAB", {0XFE,0XDE,0XAB} },
    { "FEDEABE8", {0XFE,0XDE,0XAB,0XE8} },
    { "123456789ABCDEF0", {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}},
    { "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}},
    { std::string(bigint::biguint::max_bytes*2, 'F'), std::vector<uint8_t>(bigint::biguint::max_bytes, 0xff) },
};

template<typename impl>
std::string to_s(const impl& i) {
    std::ostringstream oss;
    // Don't really care about uppercase
    oss << std::hex << std::uppercase << i;
    return oss.str();
}

template<typename impl>
impl from_be_bytes(const std::vector<uint8_t>&);

template<typename impl>
void test_hex_out()
{
    for (const auto& t : u64_test_cases) {
        FUNTLS_ASSERT_EQUAL(t.expected, to_s(impl(t.val)));
    }
    for (const auto& t : be_bytes_test_cases) {
        FUNTLS_ASSERT_EQUAL(t.expected, to_s(from_be_bytes<impl>(t.bytes)));
    }
}

template<typename impl>
void test_hex_in()
{
    for (const auto& t : u64_test_cases) {
        impl x((std::string("0x")+t.expected).c_str());
        FUNTLS_ASSERT_EQUAL(t.expected, to_s(x));
    }
    for (const auto& t : be_bytes_test_cases) {
        impl x((std::string("0x")+t.expected).c_str());
        FUNTLS_ASSERT_EQUAL(t.expected, to_s(x));
    }
}

template<typename impl>
void test_eq()
{
    // obtain some (hopefuly) distinct numbers
    std::vector<impl> xs;
    for (const auto& t : be_bytes_test_cases) {
        xs.emplace_back((std::string("0x")+t.expected).c_str());
    }
    for (size_t i = 0; i < xs.size(); ++i) {
        for (size_t j = 0; j < xs.size(); ++j) {
            FUNTLS_CHECK_BINARY(xs[i]==xs[j], ==, i==j, to_s(xs[i]) + " != " + to_s(xs[j]));
        }
    }
}

template<typename impl>
void test_add()
{
}

template<typename impl>
void test_impl()
{
    test_hex_out<impl>();
    test_hex_in<impl>();
    test_eq<impl>();
    test_add<impl>();
}

template<>
bigint::biguint from_be_bytes<bigint::biguint>(const std::vector<uint8_t>& b) {
    return bigint::biguint::from_be_bytes(b.data(), b.size());
}

#include <boost/multiprecision/cpp_int.hpp>
using boost_int = boost::multiprecision::cpp_int;
template<>
boost_int from_be_bytes<boost_int>(const std::vector<uint8_t>& b) {
    if (b.empty()) return 0;
    return boost_int("0x" + util::base16_encode(b));
}

int main()
{
    test_impl<boost_int>(); // Reference implementation
    test_impl<bigint::biguint>();
}
