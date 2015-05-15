#include "x509_io.h"

#include <istream>
#include <string>
#include <sstream>
#include <fstream>

#include <util/base_conversion.h>
#include <util/buffer.h>
#include <util/test.h>

using namespace funtls;

namespace {

// PEM is specified in RFC1421
const char* const pem_line_end = "\r\n";
const char* const cert_begin_line = "-----BEGIN CERTIFICATE-----";
const char* const cert_end_line   = "-----END CERTIFICATE-----";
const char* const pkey_begin_line = "-----BEGIN PRIVATE KEY-----";
const char* const pkey_end_line   = "-----END PRIVATE KEY-----";

std::vector<uint8_t> read_pem_data(std::istream& is, const char* const begin_line, const char* const end_line)
{
    enum { before_first_line, reading_content } state = before_first_line;

    std::string content;
    for (std::string line; std::getline(is, line);) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line == begin_line) {
            if (state == before_first_line) {
                state = reading_content;
            } else if (state == reading_content) {
                FUNTLS_CHECK_FAILURE("Two beginning markers found");
            } else {
                assert(false);
            }
         } else if (line == end_line) {
            if (state == before_first_line) {
                FUNTLS_CHECK_FAILURE("End marker reached before finding the beginning");
            } else if (state == reading_content) {
                return util::base64_decode(content);
            }
            assert(false);
        } else {
            if (state == before_first_line) {
                // skip
            } else if (state == reading_content) {
                content += line;
            } else {
                assert(false);
            }
        }
    }
    FUNTLS_CHECK_FAILURE("End reached without finishing content");
}

void write_pem_data(std::ostream& os, const char* const begin_line, const char* const end_line, const std::vector<uint8_t>& der_encoded_data)
{
    constexpr size_t max_line_width = 64;
    os << begin_line << pem_line_end;
    const auto base64_encoded_data = util::base64_encode(der_encoded_data);
    for (size_t i = 0, len = base64_encoded_data.size(); i < len; ) {
        const size_t remaining = len - i;
        const auto this_line = remaining < max_line_width ? remaining : max_line_width;
        os.write(&base64_encoded_data[i], this_line);
        os << pem_line_end;
        i += this_line;
    }
    os << end_line << pem_line_end;
}

template<typename F>
auto from_string_impl(const std::string& s, F f) -> decltype(f(std::declval<std::istream&>())) {
    std::istringstream iss(s);
    return f(iss);
}

template<typename F>
auto from_file_impl(const std::string& filename, F f) -> decltype(f(std::declval<std::istream&>())) {
    std::ifstream in(filename, std::ifstream::binary);

    if (!in || !in.is_open()) {
        FUNTLS_CHECK_FAILURE("Error opening '" + filename + "'");
    }

    auto data = f(in);

    if (!in) {
        FUNTLS_CHECK_FAILURE("Error while reading from '" + filename + "'");
    }

    if (in.peek() != std::char_traits<char>::eof()) {
        FUNTLS_CHECK_FAILURE("Error while reading from '" + filename + "'");
    }

    return data;
}

} // unnamed namespace

namespace funtls { namespace x509 {

certificate read_pem_certificate(std::istream& is)
{
    auto cert_der_data = read_pem_data(is, cert_begin_line, cert_end_line);
    assert(cert_der_data.size());
    util::buffer_view cert_buf(&cert_der_data[0], cert_der_data.size());
    return certificate::parse(asn1::read_der_encoded_value(cert_buf));
}

certificate read_pem_certificate_from_string(const std::string& s)
{
    return from_string_impl(s, &read_pem_certificate);
}

certificate read_pem_certificate_from_file(const std::string& filename)
{
    return from_file_impl(filename, &read_pem_certificate);
}

void write_pem_certificate(std::ostream& os, const std::vector<uint8_t>& der_encoded_certificate)
{
    write_pem_data(os, cert_begin_line, cert_end_line, der_encoded_certificate);
}

private_key_info read_pem_private_key(std::istream& is)
{
    auto pkey_der_data = read_pem_data(is, pkey_begin_line, pkey_end_line);
    assert(pkey_der_data.size());
    util::buffer_view pkey_buf(pkey_der_data.data(), pkey_der_data.size());
    return private_key_info::parse(asn1::read_der_encoded_value(pkey_buf));
}

private_key_info read_pem_private_key_from_string(const std::string& s)
{
    return from_string_impl(s, &read_pem_private_key);
}

private_key_info read_pem_private_key_from_file(const std::string& filename)
{
    return from_file_impl(filename, &read_pem_private_key);
}

} } // namespace funtls::x509
