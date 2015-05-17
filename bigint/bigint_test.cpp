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

const auto max_int_s = std::string(bigint::biguint::max_bytes*2, 'F');
const auto max_int_b = std::vector<uint8_t>(bigint::biguint::max_bytes, 0xff);

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
    { "FE", {0XFE} },
    { "C30", {0X0C,0X30} },
    { "8611", {0X86,0X11} },
    { "FEDE", {0XFE,0XDE} },
    { "FEDEAB", {0XFE,0XDE,0XAB} },
    { "FEDEABE8", {0XFE,0XDE,0XAB,0XE8} },
    { "123456789ABCDEF0", {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}},
    { "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}},
    { max_int_s, max_int_b },
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
            FUNTLS_CHECK_BINARY(xs[i]==xs[j], ==, i==j, to_s(xs[i]) + " != " + to_s(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]!=xs[j], !=, i==j, to_s(xs[i]) + " != " + to_s(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]<xs[j],  ==, i<j,  to_s(xs[i]) + " >= " + to_s(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]>xs[j],  ==, i>j,  to_s(xs[i]) + " <= " + to_s(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]<=xs[j], ==, i<=j, to_s(xs[i]) + " > "  + to_s(xs[j]));
            FUNTLS_CHECK_BINARY(xs[i]>=xs[j], ==, i>=j, to_s(xs[i]) + " < "  + to_s(xs[j]));
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
        auto rs = to_s<impl>(a+b);
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
        { "312", "10001", "3120312" },
        { "324141", "881D", "1AB85BEC5D" },
    };
    for (const auto& t : test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL(t.p, to_s<impl>(a*b));
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
    };
    for (const auto& t : test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        const auto m = from_hex<impl>(t.m);
        const impl res = powm(a, b, m);
        FUNTLS_ASSERT_EQUAL(t.expected, to_s(res));
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
        FUNTLS_ASSERT_EQUAL(t.expected, to_s(res));
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
        FUNTLS_ASSERT_EQUAL(t.expected, to_s(res));
    }

#define CHECK_MASK(src, mask, expected) do { \
    impl res = from_hex<impl>(src) & mask;  \
    FUNTLS_ASSERT_EQUAL(expected, to_s(res));\
} while(0)

    CHECK_MASK("ABCD", 0xFF, "CD");
    CHECK_MASK("FFFFFF", 0x01, "1");
    CHECK_MASK("FFFFFF", 0x03, "3");
    CHECK_MASK("FFFFFF", 0x88, "88");
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
    };
    for (const auto& t : test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL(t.d, to_s<impl>(a-b));
    }
}

template<typename impl>
void test_divmod()
{
    static const struct {
        const char* a;
        const char* b;
        const char* m;
    } mod_test_cases[] = {
        { "0", "2", "0" },
        { "3", "5", "3" },
        { "42", "1", "0" },
        { "6", "2", "0" },
        { "5", "2", "1" },
        { "100", "100", "0" },
        { "100", "101", "100" },
        { "B6D1", "C30", "1" },
        { "123172393182310DEAC", "100", "AC" },
    };
    for (const auto& t : mod_test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL(t.m, to_s<impl>(a%b));
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
        { "341807FDAC81", "100", "341807FDAC" },
    };
    for (const auto& t : div_test_cases) {
        const auto a = from_hex<impl>(t.a);
        const auto b = from_hex<impl>(t.b);
        FUNTLS_ASSERT_EQUAL(t.q, to_s<impl>(a/b));
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
    std::cout << "p = " << p << std::endl;
    std::cout << "q = " << q << std::endl;
    // 2. Compute n = pq.
    const impl n = p * q;
    std::cout << "n = " << n << std::endl;
    // 3. Compute phi(n) = phi(p)phi(q) =  (p − 1)(q − 1) = n - (p + q - 1)
    const impl phi_n = n - (p + q - 1);
    std::cout << "phi(n) = " << phi_n << std::endl;
    // 4. Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
    const impl e = 17;
    //assert(gcd(phi_n, e) == 1);
    // 5. Determine d as d == e^−1 (mod phi(n)); i.e., d is the multiplicative inverse of e (modulo phi(n)).
    assert(modular_inverse(42, 2017)==1969);
    const impl d = modular_inverse(e, phi_n);
    std::cout << "d = " << d << std::endl;
    assert(impl((e*d) % phi_n) == 1);

    std::cout << "Public key: (" << n << ", " << e << ")\n";
    std::cout << "Private key: " << d << std::endl;

    const impl m = 65;
    const impl c = powm(m, e, n);
    std::cout << m << " encrypted: " << c << std::endl;
    std::cout << "and decrypted: " << powm(c, d, n) << std::endl;

    const impl h = 123; // hash of message we wish to sign
    const impl s = powm(h, d, n);
    std::cout << h << " signed: " << s << std::endl;
    std::cout << "orignal hash back: " << powm(s, e, n) << std::endl;
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
//    rsa_test<impl>();
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
