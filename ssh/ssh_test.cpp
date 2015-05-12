#include <iostream>
#include <ssh/ssh.h>
#include <util/test.h>
#include <util/base_conversion.h>
#include <util/int_util.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

namespace {

std::vector<uint8_t> s2v(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::string v2s(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

std::string nl2s(const ssh::name_list& nl) {
    std::ostringstream os;
    os << nl;
    return os.str();
}

std::string parse_ssh_string(const std::vector<uint8_t>& v) {
    util::buffer_view b(v.data(), v.size());
    return v2s(ssh::get_string(b));
}

int_type parse_ssh_mpint(const std::vector<uint8_t>& v) {
    util::buffer_view b(v.data(), v.size());
    return ssh::string_to_int<int_type>(ssh::get_string(b));
}

} // unnamed namespace

int main()
{
    FUNTLS_ASSERT_EQUAL("", parse_ssh_string({0,0,0,0}));
    FUNTLS_ASSERT_THROWS(parse_ssh_string({0,0,0,2,0}), std::runtime_error);
    FUNTLS_ASSERT_EQUAL("testing", parse_ssh_string({0,0,0,7,'t','e','s','t','i','n','g'}));

    FUNTLS_ASSERT_EQUAL(int_type("0")                  , parse_ssh_mpint({0x00,0x00,0x00,0x00}));
    FUNTLS_ASSERT_EQUAL(int_type(1)                    , ssh::string_to_int<int_type>({0x01}));
    FUNTLS_ASSERT_EQUAL(int_type("0x9a378f9b2e332a7")  , parse_ssh_mpint({0x00,0x00,0x00,0x08,0x09,0xa3,0x78,0xf9,0xb2,0xe3,0x32,0xa7}));
    FUNTLS_ASSERT_EQUAL(int_type("0x80")               , parse_ssh_mpint({0x00,0x00,0x00,0x02,0x00,0x80}));
    FUNTLS_ASSERT_EQUAL(int_type("-0x1234")            , parse_ssh_mpint({0x00,0x00,0x00,0x02,0xed,0xcc}));
    FUNTLS_ASSERT_EQUAL(int_type("-0xdeadbeef")        , parse_ssh_mpint({0x00,0x00,0x00,0x05,0xff,0x21,0x52,0x41,0x11}));
    // Illegal zero repr
    FUNTLS_ASSERT_THROWS(ssh::string_to_int<int_type>({0x00}), std::runtime_error);
    FUNTLS_ASSERT_THROWS(ssh::string_to_int<int_type>({0x00,0x00,0x00,0x00}), std::runtime_error);

    using nl = ssh::name_list;
    FUNTLS_ASSERT_EQUAL(nl(), ssh::name_list::from_string(s2v("")));
    FUNTLS_ASSERT_EQUAL(nl({"zlib"}), ssh::name_list::from_string(s2v("zlib")));
    FUNTLS_ASSERT_EQUAL(nl({"zlib","none"}), ssh::name_list::from_string(s2v("zlib,none")));
    FUNTLS_ASSERT_EQUAL(nl({"zlib","none","x"}), ssh::name_list::from_string(s2v("zlib,none,x")));
    FUNTLS_ASSERT_EQUAL(nl({"zlib","none"," xyz ", " Foo12"}), ssh::name_list::from_string(s2v("zlib,none, xyz , Foo12")));
    FUNTLS_ASSERT_THROWS(ssh::name_list::from_string(s2v(",")), std::runtime_error);
    FUNTLS_ASSERT_THROWS(ssh::name_list::from_string(s2v("zlib,")), std::runtime_error);
    FUNTLS_ASSERT_THROWS(ssh::name_list::from_string(s2v(",zlib")), std::runtime_error);
    FUNTLS_ASSERT_THROWS(ssh::name_list::from_string(s2v("none,zlib,,x")), std::runtime_error);
    FUNTLS_ASSERT_THROWS(ssh::name_list::from_string(s2v("none,zlib\x9f,x")), std::runtime_error);

    FUNTLS_ASSERT_EQUAL("", nl2s({}));
    FUNTLS_ASSERT_EQUAL("zlib", nl2s(ssh::name_list({"zlib"})));
    FUNTLS_ASSERT_EQUAL("zlib,none", nl2s(ssh::name_list({"zlib","none"})));
    FUNTLS_ASSERT_EQUAL("zlib,none, 123,  AAQQ   ,X", nl2s(ssh::name_list({"zlib","none"," 123","  AAQQ   ", "X"})));
}
