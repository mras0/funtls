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
#include <x509/x509_io.h>

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

std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& a)  {
    return os << util::base16_encode(a);
}

std::vector<uint8_t> crude_get_pem_data(const std::string& s)
{
    std::string data;
    std::istringstream in(s);
    for (std::string line; std::getline(in, line);) {
        if (line.empty()) continue;
        if (line[0] == '-') continue;
        if (line.back() == '\r') line.pop_back();
        FUNTLS_CHECK_BINARY(line.size(), <=, 72, "Illegal line length: '" + line + "'");
        data += line;
    }
    return util::base64_decode(data);
}

void test_load_save(const std::vector<uint8_t>& der_data)
{
    std::ostringstream oss;

    // Write as PEM data to string
    x509::write_pem_certificate(oss, der_data);
    const auto pem_data = oss.str();

    // Did we get the expected result?
    FUNTLS_ASSERT_EQUAL(der_data, crude_get_pem_data(pem_data));

    // And can it be read?
    auto cert = x509::read_pem_certificate_from_string(pem_data);

    // Check it against the supplied data
    util::buffer_view buf{&der_data[0], der_data.size()};
    auto ccert = x509::v3_certificate::parse(asn1::read_der_encoded_value(buf));
    FUNTLS_ASSERT_EQUAL(cert.certificate_der_encoded(), ccert.certificate_der_encoded());
    FUNTLS_ASSERT_EQUAL(cert.signature_algorithm(), ccert.signature_algorithm());
    FUNTLS_ASSERT_EQUAL(cert.signature().as_vector(), ccert.signature().as_vector());
}

void test_load_save(const std::string& pem_data)
{
    const auto der_data = crude_get_pem_data(pem_data);
    test_load_save(der_data);
}

std::vector<x509::v3_certificate> read_pem_cert_chain(std::istream& in)
{
    std::vector<x509::v3_certificate> chain;
    std::cout << "\n\n\n\n\n";
    while (in && in.peek() != std::char_traits<char>::eof()) {
        chain.push_back(x509::read_pem_certificate(in));
    }
    return chain;
}

#include "test_cert0.h"
#include "test_cert1.h"
#include "test_cert_chain0.h"

int main()
{
    // TODO: Check x509::name equals operations. Only exact matches should be allowed (with order being important) etc.

    const auto cert0 = x509::read_pem_certificate_from_string(test_cert0);
    x509::verify_x509_certificate(cert0, cert0);
    test_load_save(test_cert0);
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
    FUNTLS_ASSERT_EQUAL(cert0.certificate().issuer, cert0.certificate().subject);
    // asn1::bit_string cert0.certificate().subject_public_key;
    FUNTLS_ASSERT_EQUAL(x509::sha256WithRSAEncryption, cert0.signature_algorithm());
    // asn1::bit_string cert0.signature

    const auto cert1 = x509::read_pem_certificate_from_string(test_cert1);
    test_load_save(test_cert1);
    FUNTLS_ASSERT_NOT_EQUAL(cert1.certificate().issuer, cert1.certificate().subject);
    FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate(cert1, cert1), std::runtime_error);

    {
        const auto root_cert = x509::read_pem_certificate_from_string(test_cert_chain0_root);
        x509::verify_x509_certificate(root_cert, root_cert);
        test_load_save(test_cert_chain0_root);
        FUNTLS_ASSERT_EQUAL(root_cert.certificate().issuer, root_cert.certificate().subject);

        std::istringstream chain_iss(test_cert_chain0);
        const auto chain = read_pem_cert_chain(chain_iss);
        FUNTLS_ASSERT_EQUAL(3U, chain.size());
        FUNTLS_ASSERT_EQUAL(chain[2].certificate().issuer, root_cert.certificate().subject);
        x509::verify_x509_certificate(chain[2], root_cert);
        FUNTLS_ASSERT_EQUAL(chain[1].certificate().issuer, chain[2].certificate().subject);
        x509::verify_x509_certificate(chain[1], chain[2]);
        FUNTLS_ASSERT_EQUAL(chain[0].certificate().issuer, chain[1].certificate().subject);
        x509::verify_x509_certificate(chain[0], chain[1]);

        // Check that various invalid combinations aren't allowed
        for (unsigned i = 0; i < chain.size(); ++i) {
            FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate(root_cert, chain[i]), std::runtime_error);
            for (unsigned j = 0; j < chain.size(); ++j) {
                if (i + 1 != j) {
                    FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate(chain[i], chain[j]), std::runtime_error);
                }
            }
        }
        FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate_chain(chain), std::runtime_error);
        auto complete_chain = chain; complete_chain.push_back(root_cert);
        x509::verify_x509_certificate_chain(complete_chain);
    }

    FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate_chain(std::vector<x509::v3_certificate>{}), std::runtime_error);
    FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate_chain(std::vector<x509::v3_certificate>{cert0}), std::runtime_error);
    x509::verify_x509_certificate_chain(std::vector<x509::v3_certificate>{cert0, cert0});
}
