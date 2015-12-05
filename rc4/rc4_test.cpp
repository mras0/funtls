#include <rc4/rc4.h>
#include <util/base_conversion.h>
#include <util/test.h>

using namespace funtls;

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& v)
{
    return os << util::base16_encode(v);
}

#define RC4_CHECK(expeceted, key, input)                                           \
    do {                                                                           \
        std::string          _key = key;                                           \
        std::vector<uint8_t> _data = input;                                        \
        rc4::rc4(std::vector<uint8_t>(_key.begin(), _key.end())).process(_data);   \
        FUNTLS_ASSERT_EQUAL(util::base16_decode(expeceted), _data);                \
    } while (0)
#define RC4_CHECK_STR(expeceted, key, input)                                       \
    do {                                                                           \
        std::string _input_str = input;                                            \
        std::vector<uint8_t> _input_vec(_input_str.begin(),_input_str.end());      \
        RC4_CHECK(expeceted, key, _input_vec);                                     \
    } while (0)

void rc4_test()
{
    // Tests from wikipedia
    RC4_CHECK_STR("BBF316E8D940AF0AD3", "Key", "Plaintext");
    RC4_CHECK_STR("1021BF0420", "Wiki", "pedia");
    RC4_CHECK_STR("45A01F645FC35B383552544B9BF5", "Secret", "Attack at dawn");
}

#include <iostream>
int main()
{
    try {
        rc4_test();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}