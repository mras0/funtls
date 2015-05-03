#include "x509_io.h"

#include <istream>
#include <string>
#include <sstream>

#include <util/base_conversion.h>
#include <util/buffer.h>
#include <util/test.h>

using namespace funtls;

namespace {

// PEM is specified in RFC1421
const char* const pem_line_end = "\r\n";
const char* const cert_begin_line = "-----BEGIN CERTIFICATE-----";
const char* const cert_end_line   = "-----END CERTIFICATE-----";

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

} // unnamed namespace

namespace funtls { namespace x509 {

v3_certificate read_pem_certificate(std::istream& is)
{
    auto cert_der_data = read_pem_data(is, cert_begin_line, cert_end_line);
    assert(cert_der_data.size());
    util::buffer_view cert_buf(&cert_der_data[0], cert_der_data.size());
    return v3_certificate::parse(asn1::read_der_encoded_value(cert_buf));
}

v3_certificate read_pem_certificate(const std::string& s)
{
    std::istringstream iss(s);
    return read_pem_certificate(iss);
}

void write_pem_certificate(std::ostream& os, const std::vector<uint8_t>& der_encoded_certificate)
{
    write_pem_data(os, cert_begin_line, cert_end_line, der_encoded_certificate);
}

} } // namespace funtls::x509
