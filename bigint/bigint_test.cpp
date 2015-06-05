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
//  - ...

using namespace funtls;

const auto max_int_s = std::string(bigint::biguint::max_bits/4, 'F');
const auto max_int_b = std::vector<uint8_t>(bigint::biguint::max_bits/8, 0xff);

const struct {
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

// This list should be in strictly increasing order
const struct {
    std::string          expected;
    std::vector<uint8_t> bytes;
} be_bytes_test_cases[] = {
    { "0", {0x00} },
    { "2A", {0x2A} },
    { "FE", {0xFE} },
    { "100", {0x01,0x00} },
    { "C30", {0x0C,0x30} },
    { "8611", {0x86,0x11} },
    { "FEDE", {0xFE,0xDE} },
    { "FEDEAB", {0xFE,0xDE,0xAB} },
    { "FEDEABE8", {0xFE,0xDE,0xAB,0xE8} },
    { "123456789ABCDEF0", {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}},
    { "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}},
    { max_int_s, max_int_b },
};

template<typename impl>
std::string to_hex(const impl& i) {
    std::ostringstream oss;
    // Don't really care about uppercase
    oss << std::hex << std::uppercase << i;
    return oss.str();
}

template<typename impl>
std::string to_dec(const impl& i) {
    std::ostringstream oss;
    oss << i;
    return oss.str();
}


template<typename impl>
impl from_be_bytes(const std::vector<uint8_t>&);

template<typename impl>
void test_hex_out()
{
    for (const auto& t : u64_test_cases) {
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(impl(t.val)));
    }
    for (const auto& t : be_bytes_test_cases) {
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(from_be_bytes<impl>(t.bytes)));
    }
}

template<typename impl>
void test_hex_in()
{
    for (const auto& t : u64_test_cases) {
        impl x((std::string("0x")+t.expected).c_str());
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(x));
        FUNTLS_ASSERT_EQUAL((int)static_cast<uint8_t>(t.val), (int)static_cast<uint8_t>(x));
        FUNTLS_ASSERT_EQUAL(static_cast<uint16_t>(t.val), static_cast<uint16_t>(x));
        FUNTLS_ASSERT_EQUAL(static_cast<uint32_t>(t.val), static_cast<uint32_t>(x));
        FUNTLS_ASSERT_EQUAL(t.val, static_cast<uint64_t>(x));
    }
    for (const auto& t : be_bytes_test_cases) {
        impl x((std::string("0x")+t.expected).c_str());
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(x));
    }
}

template<typename impl>
impl from_hex(const std::string& s) {
    return impl(("0x"+s).c_str());
}

template<typename impl>
void test_rel_ops()
{
    std::vector<impl> xs;
    for (const auto& t : be_bytes_test_cases) {
        xs.emplace_back(from_hex<impl>(t.expected));
    }
    for (size_t i = 0; i < xs.size(); ++i) {
        for (size_t j = 0; j < xs.size(); ++j) {
            FUNTLS_CHECK_BINARY(xs[i]==xs[j], ==, i==j, to_hex(xs[i]) + " != " + to_hex(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]!=xs[j], !=, i==j, to_hex(xs[i]) + " != " + to_hex(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]<xs[j],  ==, i<j,  to_hex(xs[i]) + " >= " + to_hex(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]>xs[j],  ==, i>j,  to_hex(xs[i]) + " <= " + to_hex(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]<=xs[j], ==, i<=j, to_hex(xs[i]) + " > "  + to_hex(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]>=xs[j], ==, i>=j, to_hex(xs[i]) + " < "  + to_hex(xs[j]));
        }
    }
}

template<typename impl>
void test_add()
{
    static const struct {
        const std::string a;
        const std::string b;
        const std::string s;
    } test_cases[] = {
        { "0", "0", "0" },
        { "0", "2", "2" },
        { "1", "2", "3" },
        { "43", "0", "43" },
        { "FF", "2", "101" },
        { "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", "F", "123456789ABCDEF0123456789ABCDEF0123456789ABCDEFF" },
        { max_int_s, "3", "2" },
    };
    for (const auto& t : test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        auto rs = to_hex<impl>(a+b);
        if (rs.length() > max_int_s.length()) {
            rs.erase(rs.begin(), rs.begin() + (rs.length()-max_int_s.length()));
            while (rs.size() > 1 && rs.front() == '0') rs.erase(rs.begin());
        }
        FUNTLS_ASSERT_EQUAL(t.s, rs);
    }
}

template<typename impl>
void test_mul()
{
    static const struct {
        const char* a;
        const char* b;
        const char* p;
    } test_cases[] = {
        { "0", "0", "0" },
        { "2", "2", "4" },
        { "0", "E", "0" },
        { "6", "0", "0" },
        { "1", "6", "6" },
        { "D", "1", "D" },
        { "2", "3", "6" },
        { "FF", "FF", "FE01" },
        { "1", "100", "100" },
        { "100", "1", "100" },
        { "F", "FFF", "EFF1" },
        { "FFF", "F", "EFF1" },
        { "312", "10001", "3120312" },
        { "324141", "881D", "1AB85BEC5D" },
        { "10000", "10000", "100000000" },
        { "10101", "AB", "ABABAB" },
        { "20202", "24", "484848" },
        { "1234", "ABCD", "C374FA4" },

        { "8FFF", "1FFF", "11FF5001" },
        { "FFFF", "1F00", "1EFFE100" },
        { "F000", "1FFF", "1DFF1000" },
        { "FF00", "1FFF", "1FDF0100" },

        { "FFF0", "1FFF", "1FFD0010" },
        { "FFFF", "1FFF", "1FFEE001" },

        { "ABAB", "1000010000", "ABAB0ABAB0000" },
        { "11111111", "11111111", "123456787654321" },
        { "15C3E8EC", "15C3E8EC", "1D9BA2363749990" },
        { "FFFFFFFFFF", "FFFFFFFFFF", "FFFFFFFFFE0000000001" },
    };
    for (const auto& t : test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL_MESSAGE(t.p, to_hex<impl>(a * b), std::string("a = ") + t.a + " b = " + t.b);
    }
}

template<typename impl>
void test_powm()
{
    static const struct {
        const char* m;
        const char* a;
        const char* b;
        const char* expected;
    } test_cases[] = {
        { "100", "0", "1", "0" },
        { "100", "0", "123455", "0" },
        { "100", "2", "4", "10" },
        { "100", "2", "8", "0" },
        { "100", "3", "134afde", "B9" },
        { "CA1", "41", "11", "AE6" },
        { "100", "1", "F0004348348242", "1" },
        { "1003", "992", "871", "B79" },
        { "100000000", "2", "8", "100" },
        { "100000000", "2", "1F", "80000000" },
        { "100000001", "2", "20", "100000000" },
        { "100000001", "2", "21", "FFFFFFFF" },
        { "100000001", "2", "22", "FFFFFFFD" },
        { "3A8F05C5", "1", "10001", "1" },
        { "3A8F05C5", "2", "1D", "20000000" },
        { "3A8F05C5", "2", "1E", "570FA3B" },
        { "3A8F05C5", "2", "3D", "EAE0463" },
        { "3A8F05C5", "2", "3E", "1D5C08C6" },
        { "3A8F05C5", "2", "10001", "29296A08" },
        { "3A8F05C5", "10", "10001", "34DC6E30" },
        { "3A8F05C5", "6B08BE5", "10001", "39A42AA1" },
    };
    for (const auto& t : test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        const auto m = from_hex<impl>(t.m);
        const impl res = powm(a, b, m);
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(res));
    }
}

template<typename impl>
void test_bitops()
{
    static const struct {
        const std::string a;
        uint32_t shift;
        const char* expected;
    } rshift_test_cases[] = {
        { "0", 0, "0" },
        { "ABCDEF",  0, "ABCDEF" },
        { "ABCDEF",  8, "ABCD" },
        { "ABCDEF", 16, "AB" },
        { "ABCDEF", 32, "0" },
        { "FE", 1, "7F" },
        { "FE", 2, "3F" },
        { "FE", 3, "1F" },
        { "FE", 4, "F" },
        { "FE", 5, "7" },
        { "FE", 6, "3" },
        { "FE", 7, "1" },
        { "FE", 8, "0" },
        { "1FF", 1, "FF" },
        { "1FF", 2, "7F" },
        { "ABCDEF",  4, "ABCDE" },
        { "123456789ABCDEF0", 23, "2468ACF135" },
        { max_int_s, bigint::biguint::max_bits, "0" },
        { max_int_s, bigint::biguint::max_bits-2, "3" },
    };
    for (const auto& t : rshift_test_cases) {
        const auto a = from_hex<impl>(t.a);
        impl res = a;
        res >>= t.shift;
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(res));
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(a >> t.shift));
    }
    static const struct {
        const std::string a;
        uint32_t shift;
        const char* expected;
    } lshift_test_cases[] = {
        { "0", 0, "0" },
        { "0", 1, "0" },
        { "0", 24, "0" },
        { "1", 0, "1" },
        { "1", 1, "2" },
        { "1", 2, "4" },
        { "1", 3, "8" },
        { "1", 4, "10" },
        { "1", 5, "20" },
        { "1", 6, "40" },
        { "1", 7, "80" },
        { "1", 8, "100" },
        { "1", 9, "200" },
        { "1", 10, "400" },
        { "FEDE", 4, "FEDE0" },
        { "FEDE", 8, "FEDE00" },
        { "FEDE", 23, "7F6F000000" },
    };
    for (const auto& t : lshift_test_cases) {
        const auto a = from_hex<impl>(t.a);
        impl res = a;
        res <<= t.shift;
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(res));
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex<impl>(a << t.shift));
    }

    static const struct {
        std::string a;
        uint8_t b;
        std::string expected;
    } and_u8_test_cases[] = {
        {"0", 0, "0"},
        {"FFFFF", 0, "0"},
        {"ABCD", 0xFF, "CD"},
        {"FFFFFF", 0x01, "1"},
        {"FFFFFF", 0x03, "3"},
        {"FFFFFF", 0x88, "88"},
        {max_int_s, 0x0, "0"},
        {max_int_s, 0xA8, "A8"},
        {max_int_s, 0xE8, "E8" },
    };
    for (const auto& t : and_u8_test_cases) {
        auto a = from_hex<impl>(t.a);
        auto b = t.b;
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex<impl>(a & b));
        a &= b;
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(a));
    }
    static const struct {
        std::string a;
        std::string b;
        std::string expected;
    } and_test_cases[] = {
        {"0", "0", "0"},
        {"FFFFF", "0", "0"},
        {"0", "FFFFF", "0"},
        {"ABCD", "FF", "CD"},
        {"FFFFFF", "01", "1"},
        {"FFFFFF", "03", "3"},
        {"FFFFFF", "88", "88"},
        {max_int_s, "0", "0"},
        {max_int_s, "A8", "A8"},
        {"0", max_int_s, "0"},
        {"21", max_int_s, "21"},
        {max_int_s, "E8", "E8" },
        {max_int_s, max_int_s, max_int_s},
    };
    for (const auto& t : and_test_cases) {
        auto a = from_hex<impl>(t.a);
        auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL_MESSAGE(t.expected, to_hex<impl>(a & b), "a " + t.a + " b " + t.b);
        a &= b;
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(a));
    }
    static const struct {
        const char* a;
        uint8_t b;
        const char* expected;
    } or_test_cases[] = {
        { "0", 0, "0" },
        { "0", 0xBC, "BC" },
        { "12345678", 0, "12345678" },
        { "1234", 0xF, "123F" },
        { "BC00", 0xAD, "BCAD" },
    };

    for (const auto& t : or_test_cases) {
        auto a = from_hex<impl>(t.a);
        a |= t.b;
        FUNTLS_ASSERT_EQUAL(t.expected, to_hex(a));
    }
}

template<typename impl>
void test_sub()
{
    static const struct {
        const char* a;
        const char* b;
        const char* d;
    } test_cases[] = {
        { "0", "0", "0" },
        { "5", "0", "5" },
        { "A", "4", "6" },
        { "100", "80", "80" },
        { "FFFFFFFFF", "2", "FFFFFFFFD" },
        {
"71E3E527067A7124732946E5881B2DA343078A7858DFF7C3CD24B434D9D555821027CD"
"56EEBF2AD9C24D705CCBAD14324A34115F1719CE1F8E79903652A514B92739A3AAC9E7"
"1C6DD494993BC7CD29FCBBF8379EF19756D1632FEDD129D4EDD4EAABB7E1D1AFBB1015"
"C373DB75E4FF00C9DE1D4F05B185C968C2B7A845BFD7AF49CA6E6CBC7736FF7E59059A"
"F6F1454B4758CADC3B96885101D2E25A77E220475B0ED13608C544E66B59DA5B1EE9E5"
"1907ACBA2764915A37B063BF5B4F032B5DD1A6829F15C1A8977887FC2D8C8902EE8ACF"
"9543E864A687E7B879FE806C2E20EE553C97ECB891C8FCDD67DC605695849C4629A77C"
"EF8D33911C85E96086BCFD9F",
"9C2A04775CD850913A06A382E0D85048BC893FF119701A88467EE08FC5F189CE21EE5A"
"FE610DB7324489A0740B534F55A4CE826295EEEB595FC6E1058012C45E943FBC5B4838"
"F453F724E6FB91E915C4CFF4530DF44AFC9F54DE7DBEA06B6F87C0D0501F28300340DA"
"0873516C7FFF3A3CA737068EBD4B1104EB7D24DEE6F9FC3171FB94D560F32E4AAF42D2"
"CBEAC46A1AB2CC53DD154B8B1FC819611FCD9DA83E632B8435696584C819C54622F853"
"95BEE3804A10C62AECBA972011C739991004A0F0617A95258C4E5275E2B6ED08CA14FC"
"CE226AB34ECF46039797037EC0B1DE7BAF4533CFBA3E71B7DEF42525C20D35899D9DFB"
"0E1179891E37C5AF8E7269",
"7147BB228F1D98D3E1EF4042053A5552FA4B013867C687A944DE35544A0F63F84205DE"
"FBF05E1D229008E6BC57A1C0E2F48F42DCB483DF343519C9554D2501F4C8A563EE6E9E"
"E379809D7454CC3B40E6F728434BE3A30BD4C3DB0F536B34826562EAE791B2878B0CD4"
"E96B6824787F018FA17617FF22C87E57BDCC2B20E0F0B54D98FC7127A1D60C500E5658"
"24255A86DD3E180FE7B9730576B31A4116C252A9B2D06E0A848FDB80E691C095D8C6EC"
"C571EDD6A71A80940CC3A9283B3D3BF1C4C1A1E1AEB4471371EC39A9B7A9D215E5C0BA"
"9875C5F9F33918727666E968AF603C76C0E8A784C20EBE6BAFFD6C316FC28F10A009DE"
"F47F22179367B19AD72E8B36"
        },
        {
"71E3E527067A7124732946E5881B2DA343078A7858DFF7C3CD24B434D9D555821027CD"
"56EEBF2AD9C24D705CCBAD14324A34115F1719CE1F8E79903652A514B92739A3AAC9E7"
"1C6DD494993BC7CD29FCBBF8379EF19756D1632FEDD129D4EDD4EAABB7E1D1AFBB1015"
"C373DB75E4FF00041AC4860C40431479C7A3256A9EBEA945FBE068514C97F2ACA3B4DD"
"C9BD300FB1737DA88F739D9C8CF2AA73D901EDE5034D34618CFAAE4BF021F420650CDD"
"6C9D6B9DA7AEA220629D1E567B60CA64F6E1AB238F773C3DBD04D64EA36F3FEFF754E4"
"92120ACF59D6B6FE7D96176FACE1A033B84731EC61833B4F1FBB547BBB46A97BB3451A"
"EA9B450AA5A42126364B7008",
"9C2A04775CD850913A06A382E0D85048BC893FF119701A88467EE08FC5F189CE21EE5A"
"FE610DB7324489A0740B534F55A4CE826295EEEB595FC6E1058012C45E943FBC5B4838"
"F453F724E6FB91E915C4CFF4530DF44AFC9F54DE7DBEA06B6F87C0D0501F28300340DA"
"0873516C7FFF3A3CA737068EBD4B1104EB7D24DEE6F9FC3171FB94D560F32E4AAF42D2"
"CBEAC46A1AB2CC53DD154B8B1FC819611FCD9DA83E632B8435696584C819C54622F853"
"95BEE3804A10C62AECBA972011C739991004A0F0617A95258C4E5275E2B6ED08CA14FC"
"CE226AB34ECF46039797037EC0B1DE7BAF4533CFBA3E71B7DEF42525C20D35899D9DFB"
"0E1179891E37C5AF8E7269",
"7147BB228F1D98D3E1EF4042053A5552FA4B013867C687A944DE35544A0F63F84205DE"
"FBF05E1D229008E6BC57A1C0E2F48F42DCB483DF343519C9554D2501F4C8A563EE6E9E"
"E379809D7454CC3B40E6F728434BE3A30BD4C3DB0F536B34826562EAE791B2878B0CD4"
"E96B6824787F00C9DE1D4F05B185C968C2B7A845BFD7AF49CA6E6CBC7736FF7E59059A"
"F6F1454B4758CADC3B96885101D2E25A77E220475B0ED13608C544E66B59DA5B1EE9E5"
"1907ACBA2764915A37B063BF5B4F032B5DD1A6829F15C1A8977887FC2D8C8902EE8ACF"
"9543E864A687E7B879FE806C2E20EE553C97ECB891C8FCDD67DC605695849C4629A77C"
"EF8D33911C85E96086BCFD9F",
        },
    };
    for (const auto& t : test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL(t.d, to_hex<impl>(a-b));
    }
}

template<typename impl>
void test_divmod()
{
    static const struct {
        const char* a;
        const char* b;
        const char* r;
    } mod_test_cases[] = {
        { "0", "2", "0" },
        { "3", "5", "3" },
        { "42", "1", "0" },
        { "6", "2", "0" },
        { "5", "2", "1" },
        { "F", "10", "F" },
        { "FF", "10", "F" },
        { "FFF", "10", "F" },
        { "FFFF", "10", "F" },
        { "100", "100", "0" },
        { "100", "101", "100" },
        { "B6D1", "C30", "1" },
        { "123456789ABCDEF", "100", "EF" },
        { "123172393182310DEAC", "100", "AC" },
        { "39AABC8699", "3A8F05C5", "5F2D8AD" },
        { "1D9BA2363749990", "3A8F05C5", "52178E" },
        { "383FE991CA66800489155DCD69E8426C427", "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB", "3FE991CA66800489155DCD69E8426C887" },
        { "B83FE991CA66800489155DCD69E8426BA2779453994AC90ED284034DA565ECF", "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB", "2C88C77849D64AE9147DDEB88E69C83FC" },
    };
    for (const auto& t : mod_test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL_MESSAGE(t.r, to_hex<impl>(a % b), std::string("a = ") + t.a + " b = " + t.b);
    }
    static const struct {
        const char* a;
        const char* b;
        const char* q;
    } div_test_cases[] = {
        { "0", "10", "0" },
        { "1", "1", "1" },
        { "6", "2", "3" },
        { "7", "2", "3" },
        { "80", "20", "4" },
        { "F", "10", "0" },
        { "FF", "10", "F" },
        { "FFF", "10", "FF" },
        { "FFFF", "10", "FFF" },
        { "341807FDAC81", "100", "341807FDAC" },
        { "FFFFFFFFFFFF", "10", "FFFFFFFFFFF" },
    };
    for (const auto& t : div_test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL_MESSAGE(t.q, to_hex<impl>(a / b), std::string("a = ") + t.a + " b = " + t.b);
    }
    const auto a = from_hex<impl>("C844A98E3372D67F562BD881DA8EA66CA71DF16DEAB1541CE7D68F2243A37665C3F07D3DD6E651CCD17A822DB5794C54EF31305699A6C77C043AC87CAFC022A30A2A717A4AA6B026B0C1C818CFC16ADBAAE33C47B0803152F7E424B784DF28616D828561A41BDD66BD220CB46CD288CE65CCAF9682B20C625A84EF28C63E38E9630DAA872270FA1580CB170BFC492B806C017661DAB0E0C90A12F68A98A9827182913FF626EFDDFBF8AE8F1D40DA8D13A90138686884BAD19DB776BB4812F7E3B288B47114E486FA2DE43011E1D5D7CA8DAF474CB210CE962AAFEE552F192CA032BA2B51CFE183226EB21CED3B4B3C09362B61F152D7C7E651E12651E915FC9F67F39338D6D21F55FB4E79F0B2BE4D4900D442D567BACF7B6DEFCD5818B050A40DB6EAB9AD76A7F349196DCC5D15CC3369E1181E03D3B24DA9CF120AA7403F400E7E4ECA532EAC2449EA7FECC41979D035A8E4ACCEA38E1B9A33D733BEA2F430362BD36F68440CCC4DC3A7F07B7A7C8FCDD02231F69CE3574568F303D6EB2916874D09F2D69E15E633C80B8FF4E9BAA56ED3ACE0F65AFB4360C372A6FD0D5629FDB6E3D832AD3D33D610B243EA22FE66F21941071A83B252201705EBC8E8F2A5CC01112AC8E4342850A637BB03E511B206599B9D4E8E1EBCEB1E820D569E31C50D9FCCB16C41315F652615A02603C69FE9BA03E78C64FECC034AA783ADEA213B");
    const auto d = from_hex<impl>("DDF13806DF4018EEA435061A6F70A6B44183D0D27874BA4E9452A0D749D9B9839E68B71FF5EA308A53A5B067D9BCBA8CABFCE273EBAA6C08E25517CFFFB93939ABF568B3DB0ABC90D59E3BF399C5BA0647E8FCFC54C7B1ACD9176E823CCF69B401AC5A305D36273B8E000E146B4D0F4CE88150719AD06661EA69355F0EAD21261BC3C92C7A64D2A7E648226828367DC90E69CB3A930D29DFE7B37DD454F57B811E8D057F9D4C51FDC07A8638CCDC0A0F2377EEB86AF6D5AFC84655092D84F3AFDF5854B6F2951623A970238A65C632BF3A62F0D11DFEAD887F1969A6700A2ACE5976C4828FEFF1BDFC569118A33C1AA324C25D07020AD6E26EB05FA9759129B1C41A2062742A3F8A8200872320F65C4C789B70DAC4F6EC9616182962BD295A79F6D15CC956F4895D6848828C0A1181E289493F4C7BEDEE9AC744C9BE3B0399365DA3400B713DB294D2783DFA3316B11BF01B965BC4DD26E8495E05C3DF756BB4E00D1B146640551C0AD22E7A707602D6C745F759B9C0B504BBBE8EFA47F1C55C9182D04A126A7C0270CBF6A62F8EA92A97A28C9C37CE1BFF4F87B325AAB97254371842523A60AE373ACEE6CE09046D0D3D0FCBF1B535F77D5E4C7E4009DFCDBD480A0C602D512050242EC965F93BEBB6E27740F54200221088719A19DD38BC24A16268F0F4177C88BFE3479EA4089E0F6B31E3148E4A3EF19B79858E9B0E8D");
    const impl q = a/231;
    const impl r = a%231;
    FUNTLS_ASSERT_EQUAL(d, q);
    FUNTLS_ASSERT_EQUAL(0, r);
}

#include <util/int_util.h>
template<typename impl>
void rsa_test()
{
    // 1. Choose two distinct prime numbers p and q.
    const impl p = 61;
    const impl q = 53;
    //std::cout << "p = " << p << std::endl;
    //std::cout << "q = " << q << std::endl;
    // 2. Compute n = pq.
    const impl n = p * q;
    //std::cout << "n = " << n << std::endl;
    // 3. Compute phi(n) = phi(p)phi(q) =  (p − 1)(q − 1) = n - (p + q - 1)
    const impl phi_n = n - (p + q - 1);
    //std::cout << "phi(n) = " << phi_n << std::endl;
    // 4. Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
    const impl e = 17;
    //assert(gcd(phi_n, e) == 1);
    // 5. Determine d as d == e^−1 (mod phi(n)); i.e., d is the multiplicative inverse of e (modulo phi(n)).
    FUNTLS_ASSERT_EQUAL(modular_inverse(impl(42), impl(2017)),impl(1969));
    const impl d = modular_inverse(e, phi_n);
    //std::cout << "d = " << d << std::endl;
    FUNTLS_ASSERT_EQUAL(impl((e*d) % phi_n), 1);

    //std::cout << "Public key: (" << n << ", " << e << ")\n";
    //std::cout << "Private key: " << d << std::endl;

    const impl m = 65;
    const impl c = powm(m, e, n);
    //std::cout << m << " encrypted: " << c << std::endl;
    const impl dm = powm(c, d, n);
    //std::cout << "and decrypted: " << dm << std::endl;
    FUNTLS_ASSERT_EQUAL(m, dm);

    const impl h = 123; // hash of message we wish to sign
    const impl s = powm(h, d, n);
    //std::cout << h << " signed: " << s << std::endl;
    const impl dh = powm(s, e, n);
    //std::cout << "orignal hash back: " << dh << std::endl;
    FUNTLS_ASSERT_EQUAL(h, dh);

    {
        auto sig_int = impl("1292096585430913175519254898032395243462811323906515226554109972004180658954859379941696658621471242846515079179717576618845623427098912978283799951696320091470122356297901501325256605959695524225415513932171913482053094408005941656185209127872354901965306664437702709542046633385218633626696287279304285124912556256930575413122875114673482785274590556733203148774836729083330959590105395524827262154584116592716387459783088847245994061585204886768758012681844214432141042086602590179087711616687868428020288032797041180520168574827807538102230289873329301503180995385059291223074441034065185713657450277277761969287");
        auto pk_exp  = impl("65537");
        auto pk_mod  = impl("24954997646621834761449361884286414165480008273223744310080315375803319523260216855934100447201664306431721005429546282762704393140191840338713076689984056264190995701894141368229539117693257565423336415750689721978540066555915380965973261977497616774408471314998180653685000389604770546408396387001860894640592821199977972059596526292354557985299637881425226355986468353901257309811384609470173861328663540424702321793095880089688714459044144974116455371251817951571066409202081916069323963479466362034024225801206214311616562135066160059514001555341780438164781033434293730782091550172964525859915795650182985987109");
        auto decoded = impl("986236757547332986472011617696226561292849812918563355472727826767720188564083584387121625107510786855734801053524719833194566624465665316622563244215340671405971599343902468620306327831715457360719532421388780770165778156818229863337344187575566725786793391480600129482653072861971002459947277805295727097226389568776499707662505334062639449916265137796823793276300221537201727072401742985542559596685092673521228140822200236743113743661549252453726123450722876929538747702356573783116197523966334991563351853851212597377279504828784773461324331554913538750469049379906172091422629105701079342533743285829650120");

        FUNTLS_ASSERT_EQUAL(decoded, powm(sig_int, pk_exp, pk_mod));
    }
}

template<typename impl>
void test_dec_io()
{
    const struct {
        const char* hex;
        const char* dec;
    } test_cases[] = {
        {"0x0"                 , "0"                    },
        {"0x2A"                , "42"                   },
        {"0x100"               , "256"                  },
        {"0x29A"               , "666"                  },
        {"0x539"               , "1337"                 },
        {"0x7FFF"              , "32767"                },
        {"0x10230421723043"    , "4542100275343427"     },
        {"0x123456789ABCDEF"   , "81985529216486895"    },
        {"0xAA00BB00CC00DD"    , "47851549213065437"    },
        {"0xA0AB00BC00C0DD00"  , "11577348074552483072" },
        {"0xAA00BB00CC00DD00"  , "12249996598544751872" },
        {"0xFFFFFFFFFFFFFFFF"  , "18446744073709551615" },
        {"0x10000000000000000" , "18446744073709551616" },
    };
    for (const auto& t : test_cases) {
        FUNTLS_ASSERT_EQUAL_MESSAGE(impl(t.hex), impl(t.dec), t.hex);
        FUNTLS_ASSERT_EQUAL(t.dec, to_dec(impl(t.hex)));
    }
}

template<typename impl>
void test_impl()
{
    test_hex_out<impl>();
    test_hex_in<impl>();
    test_rel_ops<impl>();
    test_add<impl>();
    test_mul<impl>();
    test_bitops<impl>();
    test_sub<impl>();
    test_divmod<impl>();
    test_powm<impl>();
    test_dec_io<impl>();
    rsa_test<impl>();
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
