#include "base_conversion.h"
#include "test.h"
#include <stdexcept>

template<typename T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& vec)
{
    os << "{";
    for (const auto& x : vec) {
        os << " " << x;
    }
    os << " }";
    return os;
}

void base16_test()
{
    static const struct {
        const char* base16;
        std::vector<uint8_t> bytes;
    } vector_test_cases[] = {
        {"", {}},
        {"00", {0x00}},
        {"00FE", {0,0xfe}},
        {"1234", {0x12,0x34}},
        {"0123456789ABCDEF", {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}},
        // Test vectors from https://tools.ietf.org/html/rfc4648 section 10
        {"66", {'f'}},
        {"666F", {'f','o'}},
        {"666F6F", {'f','o','o'}},
        {"666F6F62", {'f','o','o','b'}},
        {"666F6F6261", {'f','o','o','b','a'}},
        {"666F6F626172", {'f','o','o','b','a','r'}},
    };

    using namespace funtls::util;
    for (const auto& test_case : vector_test_cases) {
        FUNTLS_ASSERT_EQUAL(test_case.base16, base16_encode(test_case.bytes));
        FUNTLS_ASSERT_EQUAL(test_case.bytes, base16_decode(test_case.base16));
    }

    uint8_t arr[] = { 0xaa, 0x55 };
    FUNTLS_ASSERT_EQUAL("", base16_encode(arr, 0));
    FUNTLS_ASSERT_EQUAL("AA", base16_encode(arr, 1));
    FUNTLS_ASSERT_EQUAL("AA55", base16_encode(arr, sizeof(arr)));

    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{}), base16_decode("AA55", 0));
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0xaa}), base16_decode("Aa55", 2));
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0xaa,0x55}), base16_decode("aa55", 4));

    FUNTLS_ASSERT_THROWS(base16_decode("aa", 1), std::runtime_error);
    FUNTLS_ASSERT_THROWS(base16_decode("ga", 2), std::runtime_error);
    FUNTLS_ASSERT_THROWS(base16_decode("ag", 2), std::runtime_error);
    FUNTLS_ASSERT_THROWS(base16_decode("xy", 2), std::runtime_error);
}

std::string vec2str(const std::vector<uint8_t>& vec)
{
    if (vec.empty()) return "";
    return std::string(reinterpret_cast<const char*>(&vec[0]), vec.size());
}

std::vector<uint8_t> str2vec(const std::string& s)
{
    if (s.empty()) return {};
    auto data = reinterpret_cast<const uint8_t*>(s.data());
    return std::vector<uint8_t>(data, data+s.length());
}

#include <iostream>

void base64_test()
{
    static const struct {
        const std::string plain;
        const std::string base64;
    } base64_test_cases[] = {
        // Test vectors from https://tools.ietf.org/html/rfc4648 section 10
        { "", "" },
        { "f", "Zg==" },
        { "fo", "Zm8=" },
        { "foo", "Zm9v" },
        { "foob", "Zm9vYg==" },
        { "fooba", "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },

        // TODO: Test non printable characters
    };

    using namespace funtls::util;
    for (const auto& test_case : base64_test_cases) {
        FUNTLS_ASSERT_EQUAL_MESSAGE(test_case.base64, test_case.plain, vec2str(base64_decode(test_case.base64)));
        FUNTLS_ASSERT_EQUAL_MESSAGE(test_case.plain,  test_case.base64, base64_encode(str2vec(test_case.plain)));
        // TODO:test non-vector/non-string versions
    }
    // TODO: Test throws
}

int main()
{
    base16_test();
    base64_test();
}
