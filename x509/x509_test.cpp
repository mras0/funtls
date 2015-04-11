#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cassert>
#include <iomanip>
#include <array>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

#include <util/base_conversion.h>
#include <util/buffer.h>
#include <asn1/asn1.h>

#include <x509/x509.h>
#include <x509/x509_rsa.h>

#include <util/test.h>
#include <hash/hash.h>

using namespace funtls;

void print_x509_v3(const x509::v3_certificate& cert)
{
    auto c = cert.certificate();
    std::cout << "Certificate:" << std::endl;
    std::cout << " Serial number: 0x" << std::hex << c.serial_number.as<int_type>() << std::dec << std::endl;
    std::cout << " Signature algorithm: " << c.signature_algorithm <<  std::endl;
    std::cout << " Issuer: " << c.issuer << std::endl;
    std::cout << " Validity: Between " << c.validity_not_before << " and " << c.validity_not_after << std::endl;
    std::cout << " Subject: " << c.subject << std::endl;
    std::cout << " Subject public key algorithm: " << c.subject_public_key_algo << std::endl;
    std::cout << "Signature algorithm: " << cert.signature_algorithm() << std::endl;
}

void check_x509_v3(const x509::v3_certificate& cert)
{
    auto c = cert.certificate();
    FUNTLS_CHECK_BINARY(c.signature_algorithm, ==, x509::sha256WithRSAEncryption, "Unsupported signature algorithm");

    // TODO: Check that it's self-signed

    auto s_pk = rsa_public_key_from_certificate(cert);
    std::cout << " Subject public key: n=0x" << util::base16_encode(s_pk.modolus.as_vector())
        << " e=0x" << util::base16_encode(s_pk.public_exponent.as_vector()) << std::endl;
    FUNTLS_CHECK_BINARY(s_pk.key_length() & (s_pk.key_length()-1), ==, 0, "Non pow2 key length?");

    assert(cert.signature_algorithm() == x509::sha256WithRSAEncryption);
    auto sig_value = cert.signature().as_vector();
    std::cout << " " << sig_value.size() << " bits" << std::endl;
    std::cout << " " << util::base16_encode(sig_value) << std::endl;

    // Decode the signature using the issuers public key (here using the subjects PK since the cert is selfsigned)
    const auto issuer_pk = s_pk;
    auto digest = x509::pkcs1_decode(issuer_pk, cert.signature().as_vector());
    std::cout << "Digest algorithm: " << digest.digest_algorithm << std::endl;
    assert(digest.digest_algorithm == x509::id_sha256);
    std::cout << "Digest: " << util::base16_encode(digest.digest) << std::endl;

    const auto& cert_buf = cert.certificate_der_encoded();
    const auto calced_digest = hash::sha256{}.input(cert_buf).result();
    std::cout << "Calculated digest: " << util::base16_encode(calced_digest) << std::endl;

    FUNTLS_ASSERT_EQUAL(calced_digest.size(), digest.digest.size());

    if (!std::equal(calced_digest.begin(), calced_digest.end(), digest.digest.begin())) {
        throw std::runtime_error("Digest mismatch in " + std::string(__PRETTY_FUNCTION__) + " Calculated: " +
                util::base16_encode(calced_digest) + " Expected: " +
                util::base16_encode(digest.digest));
    }
}

std::vector<uint8_t> read_file(const std::string& filename)
{
    std::ifstream in(filename, std::ios::binary);
    if (!in || !in.is_open()) {
        throw std::runtime_error("Could not open " + filename);
    }
    in.seekg(0, std::ifstream::end);
    std::vector<uint8_t> buffer(in.tellg());
    in.seekg(0, std::ifstream::beg);
    in.read(reinterpret_cast<char*>(&buffer[0]), buffer.size());
    if (!in) {
        throw std::runtime_error("Error reading from " + filename);
    }
    return buffer;
}

#include "test_cert0.h"

std::vector<uint8_t> read_pem_cert(std::istream& is)
{
    static const char* const begin_line = "-----BEGIN CERTIFICATE-----";
    static const char* const end_line   = "-----END CERTIFICATE-----";

    enum { before_first_line, reading_content } state = before_first_line;

    std::string content;
    for (std::string line; std::getline(is, line);) {
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

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& a)  {
    return os << util::base16_encode(a);
}

x509::v3_certificate certificate_from_pem_string(const std::string& pem_data)
{
    std::istringstream cert_pem_data(pem_data);
    auto cert_der_data = read_pem_cert(cert_pem_data);
    assert(cert_der_data.size());
    util::buffer_view cert_buf(&cert_der_data[0], cert_der_data.size());
    return x509::v3_certificate::parse(asn1::read_der_encoded_value(cert_buf));
 }

int main()
{
    const auto cert0 = certificate_from_pem_string(test_cert0);
    print_x509_v3(cert0);
    check_x509_v3(cert0);
    FUNTLS_ASSERT_EQUAL(int_type("11259235216357634699"), cert0.certificate().serial_number.as<int_type>());
    FUNTLS_ASSERT_EQUAL(x509::sha256WithRSAEncryption, cert0.certificate().signature_algorithm);
    auto a = cert0.certificate().issuer.attributes();
    FUNTLS_ASSERT_EQUAL(4, a.size());
    FUNTLS_ASSERT_EQUAL(x509::attribute_type::country_name, a[0].first);
    FUNTLS_ASSERT_EQUAL("DK", a[0].second);
    FUNTLS_ASSERT_EQUAL(x509::attribute_type::state_or_province_name, a[1].first);
    FUNTLS_ASSERT_EQUAL("Some-State", a[1].second);
    FUNTLS_ASSERT_EQUAL(x509::attribute_type::organization_name, a[2].first);
    FUNTLS_ASSERT_EQUAL("Internet Widgits Pty Ltd", a[2].second);
    FUNTLS_ASSERT_EQUAL(x509::attribute_type::common_name, a[3].first);
    FUNTLS_ASSERT_EQUAL("localhost", a[3].second);
    FUNTLS_ASSERT_EQUAL("150321135936Z", cert0.certificate().validity_not_before.as_string());
    FUNTLS_ASSERT_EQUAL("160320135936Z", cert0.certificate().validity_not_after.as_string());
    a = cert0.certificate().subject.attributes();
    FUNTLS_ASSERT_EQUAL(4, a.size());
    FUNTLS_ASSERT_EQUAL(x509::attribute_type::country_name, a[0].first);
    FUNTLS_ASSERT_EQUAL("DK", a[0].second);
    FUNTLS_ASSERT_EQUAL(x509::attribute_type::state_or_province_name, a[1].first);
    FUNTLS_ASSERT_EQUAL("Some-State", a[1].second);
    FUNTLS_ASSERT_EQUAL(x509::attribute_type::organization_name, a[2].first);
    FUNTLS_ASSERT_EQUAL("Internet Widgits Pty Ltd", a[2].second);
    FUNTLS_ASSERT_EQUAL(x509::attribute_type::common_name, a[3].first);
    FUNTLS_ASSERT_EQUAL("localhost", a[3].second);
    FUNTLS_ASSERT_EQUAL(x509::rsaEncryption, cert0.certificate().subject_public_key_algo);
    // asn1::bit_string cert0.certificate().subject_public_key;
    FUNTLS_ASSERT_EQUAL(x509::sha256WithRSAEncryption, cert0.signature_algorithm());
    // asn1::bit_string cert0.signature
}
