#include "base_conversion.h"
#include "test.h"

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

int main()
{
    static const struct {
        const char* base16;
        std::vector<uint8_t> bytes;
    } vector_test_cases[] = {
        {"", {}},
        {"00", {0x00}},
        {"00fe", {0,0xfe}},
        {"1234", {0x12,0x34}},
        {"0123456789abcdef", {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}},
    };

    using namespace funtls::util;
    for (const auto& test_case : vector_test_cases) {
        FUNTLS_ASSERT_EQUAL(test_case.base16, base16_encode(test_case.bytes));
        FUNTLS_ASSERT_EQUAL(test_case.bytes, base16_decode(test_case.base16));
    }

    uint8_t arr[] = { 0xaa, 0x55 };
    FUNTLS_ASSERT_EQUAL("", base16_encode(arr, 0));
    FUNTLS_ASSERT_EQUAL("aa", base16_encode(arr, 1));
    FUNTLS_ASSERT_EQUAL("aa55", base16_encode(arr, sizeof(arr)));

    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{}), base16_decode("aa55", 0));
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0xaa}), base16_decode("aa55", 2));
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0xaa,0x55}), base16_decode("aa55", 4));
}
