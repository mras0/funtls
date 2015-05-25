#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cassert>
#include <iomanip>
#include <array>

#ifdef USE_FUNTLS_BIGINT
#include <bigint/bigint.h>
using int_type = funtls::bigint::biguint;
#else
#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;
#endif

#include <util/base_conversion.h>
#include <util/buffer.h>
#include <asn1/asn1.h>

#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <x509/x509_io.h>

#include <util/test.h>
#include <hash/hash.h>

using namespace funtls;

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
    auto ccert = x509::certificate::parse(asn1::read_der_encoded_value(buf));
    FUNTLS_ASSERT_EQUAL(cert.certificate_der_encoded(), ccert.certificate_der_encoded());
    FUNTLS_ASSERT_EQUAL(cert.signature_algorithm(), ccert.signature_algorithm());
    FUNTLS_ASSERT_EQUAL(cert.signature().as_vector(), ccert.signature().as_vector());
}

void test_load_save(const std::string& pem_data)
{
    const auto der_data = crude_get_pem_data(pem_data);
    test_load_save(der_data);
}

std::vector<x509::certificate> read_pem_cert_chain(std::istream& in)
{
    std::vector<x509::certificate> chain;
    while (in && in.peek() != std::char_traits<char>::eof()) {
        chain.push_back(x509::read_pem_certificate(in));
    }
    return chain;
}

#include "test_cert0.h"
#include "test_cert1.h"
#include "test_cert2.h"
#include "test_cert3.h"
#include "test_cert_chain0.h"

void test_cert()
{
    const auto cert0 = x509::read_pem_certificate_from_string(test_cert0);
    x509::verify_x509_signature(cert0, cert0);
    test_load_save(test_cert0);
    FUNTLS_ASSERT_EQUAL(int_type("11259235216357634699"), cert0.tbs().serial_number.as<int_type>());
    FUNTLS_ASSERT_EQUAL(x509::id_sha256WithRSAEncryption, cert0.tbs().signature_algorithm.id());
    FUNTLS_ASSERT_EQUAL(2, cert0.tbs().signature_algorithm.parameters().size());
    FUNTLS_ASSERT_EQUAL(util::base16_decode("0500"), cert0.tbs().signature_algorithm.parameters());
    FUNTLS_ASSERT_EQUAL(true, cert0.tbs().signature_algorithm.null_parameters());
    auto a = cert0.tbs().issuer.attributes();
    FUNTLS_ASSERT_EQUAL(4, a.size());
    FUNTLS_ASSERT_EQUAL(x509::attr_countryName, a[0].first);
    FUNTLS_ASSERT_EQUAL("DK", a[0].second.as_string());
    FUNTLS_ASSERT_EQUAL(x509::attr_stateOrProvinceName, a[1].first);
    FUNTLS_ASSERT_EQUAL("Some-State", a[1].second.as_string());
    FUNTLS_ASSERT_EQUAL(x509::attr_organizationName, a[2].first);
    FUNTLS_ASSERT_EQUAL("Internet Widgits Pty Ltd", a[2].second.as_string());
    FUNTLS_ASSERT_EQUAL(x509::attr_commonName, a[3].first);
    FUNTLS_ASSERT_EQUAL("localhost", a[3].second.as_string());
    FUNTLS_ASSERT_EQUAL("150321135936Z", cert0.tbs().validity_not_before.as_string());
    FUNTLS_ASSERT_EQUAL("160320135936Z", cert0.tbs().validity_not_after.as_string());
    a = cert0.tbs().subject.attributes();
    FUNTLS_ASSERT_EQUAL(4, a.size());
    FUNTLS_ASSERT_EQUAL(x509::attr_countryName, a[0].first);
    FUNTLS_ASSERT_EQUAL("DK", a[0].second.as_string());
    FUNTLS_ASSERT_EQUAL(x509::attr_stateOrProvinceName, a[1].first);
    FUNTLS_ASSERT_EQUAL("Some-State", a[1].second.as_string());
    FUNTLS_ASSERT_EQUAL(x509::attr_organizationName, a[2].first);
    FUNTLS_ASSERT_EQUAL("Internet Widgits Pty Ltd", a[2].second.as_string());
    FUNTLS_ASSERT_EQUAL(x509::attr_commonName, a[3].first);
    FUNTLS_ASSERT_EQUAL("localhost", a[3].second.as_string());
    FUNTLS_ASSERT_EQUAL(x509::id_rsaEncryption, cert0.tbs().subject_public_key_algo.id());
    FUNTLS_ASSERT_EQUAL(true, cert0.tbs().subject_public_key_algo.null_parameters());
    FUNTLS_ASSERT_EQUAL(cert0.tbs().issuer, cert0.tbs().subject);
    // asn1::bit_string cert0.tbs().subject_public_key;
    FUNTLS_ASSERT_EQUAL(x509::id_sha256WithRSAEncryption, cert0.signature_algorithm().id());
    FUNTLS_ASSERT_EQUAL(2, cert0.signature_algorithm().parameters().size());
    FUNTLS_ASSERT_EQUAL(util::base16_decode("0500"), cert0.signature_algorithm().parameters());
    FUNTLS_ASSERT_EQUAL(true, cert0.signature_algorithm().null_parameters());
    // asn1::bit_string cert0.signature

    const auto cert1 = x509::read_pem_certificate_from_string(test_cert1);
    test_load_save(test_cert1);
    FUNTLS_ASSERT_NOT_EQUAL(cert1.tbs().issuer, cert1.tbs().subject);
    FUNTLS_ASSERT_THROWS(x509::verify_x509_signature(cert1, cert1), std::runtime_error);

    const auto cert2 = x509::read_pem_certificate_from_string(test_cert2);
    FUNTLS_ASSERT_EQUAL(cert2.tbs().issuer, cert2.tbs().subject);
    x509::verify_x509_signature(cert2, cert2);
    test_load_save(test_cert2);

    const auto cert3 = x509::read_pem_certificate_from_string(test_cert3);
    std::ostringstream cert3_subject_name;
    cert3_subject_name << cert3.tbs().subject;
    FUNTLS_ASSERT_EQUAL(int_type("0x055556bcf25ea43535c3a40fd5ab4572"), cert3.tbs().serial_number.as<int_type>());
    FUNTLS_ASSERT_EQUAL(cert3_subject_name.str(), test_cert3_subject_name);
    FUNTLS_ASSERT_EQUAL(cert3.tbs().issuer, cert3.tbs().subject);
    FUNTLS_ASSERT_EQUAL(x509::id_ecdsaWithSHA384, cert3.tbs().signature_algorithm.id());
    FUNTLS_ASSERT_EQUAL("", util::base16_encode(cert3.tbs().signature_algorithm.parameters()));
    FUNTLS_ASSERT_EQUAL(x509::id_ecPublicKey, cert3.tbs().subject_public_key_algo.id());
    FUNTLS_ASSERT_EQUAL((asn1::object_id{1,3,132,0,34}), x509::from_buffer<asn1::object_id>(cert3.tbs().subject_public_key_algo.parameters())); //secp384r1
    FUNTLS_ASSERT_EQUAL(x509::id_ecdsaWithSHA384, cert3.signature_algorithm().id());
    FUNTLS_ASSERT_EQUAL(true, cert3.signature_algorithm().null_parameters());
    x509::verify_x509_signature(cert3, cert3);
    test_load_save(test_cert3);

    {
        const auto root_cert = x509::read_pem_certificate_from_string(test_cert_chain0_root);
        x509::verify_x509_signature(root_cert, root_cert);
        test_load_save(test_cert_chain0_root);
        FUNTLS_ASSERT_EQUAL(root_cert.tbs().issuer, root_cert.tbs().subject);

        std::istringstream chain_iss(test_cert_chain0);
        const auto chain = read_pem_cert_chain(chain_iss);
        FUNTLS_ASSERT_EQUAL(3U, chain.size());
        FUNTLS_ASSERT_EQUAL(chain[2].tbs().issuer, root_cert.tbs().subject);
        x509::verify_x509_signature(chain[2], root_cert);
        FUNTLS_ASSERT_EQUAL(chain[1].tbs().issuer, chain[2].tbs().subject);
        x509::verify_x509_signature(chain[1], chain[2]);
        FUNTLS_ASSERT_EQUAL(chain[0].tbs().issuer, chain[1].tbs().subject);
        x509::verify_x509_signature(chain[0], chain[1]);

        // Check that various invalid combinations aren't allowed
        for (unsigned i = 0; i < chain.size(); ++i) {
            FUNTLS_ASSERT_THROWS(x509::verify_x509_signature(root_cert, chain[i]), std::runtime_error);
            for (unsigned j = 0; j < chain.size(); ++j) {
                if (i + 1 != j) {
                    FUNTLS_ASSERT_THROWS(x509::verify_x509_signature(chain[i], chain[j]), std::runtime_error);
                }
            }
        }
        FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate_chain(chain), std::runtime_error);
        auto complete_chain = chain; complete_chain.push_back(root_cert);
        x509::verify_x509_certificate_chain(complete_chain);
    }

    FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate_chain(std::vector<x509::certificate>{}), std::runtime_error);
    FUNTLS_ASSERT_THROWS(x509::verify_x509_certificate_chain(std::vector<x509::certificate>{cert0}), std::runtime_error);
    x509::verify_x509_certificate_chain(std::vector<x509::certificate>{cert0, cert0});
}

#include "test_pkey0.h"
void test_pkey()
{
    auto pki = x509::read_pem_private_key_from_string(test_pkey0);
    FUNTLS_ASSERT_EQUAL(0,                      pki.version.as<int>());
    FUNTLS_ASSERT_EQUAL(x509::id_rsaEncryption, pki.algorithm);

    auto pkey = x509::rsa_private_key_from_pki(pki);

#if 0
#define P(f) std::cout << #f << " " << std::hex << pkey.f.as<int_type>() << std::endl
    P(version);
    P(modulus);
    P(public_exponent);
    P(private_exponent);
    P(prime1);
    P(prime2);
    P(exponent1);
    P(exponent2);
    P(coefficient);
#undef P
#endif
    FUNTLS_ASSERT_EQUAL(0,            pkey.version.as<int>());
    FUNTLS_ASSERT_EQUAL(test_pkey0_n, util::base16_encode(pkey.modulus.as_vector()));
    FUNTLS_ASSERT_EQUAL(test_pkey0_e, util::base16_encode(pkey.public_exponent.as_vector()));
    FUNTLS_ASSERT_EQUAL(test_pkey0_d, util::base16_encode(pkey.private_exponent.as_vector()));
    FUNTLS_ASSERT_EQUAL(test_pkey0_p, util::base16_encode(pkey.prime1.as_vector()));
    FUNTLS_ASSERT_EQUAL(test_pkey0_q, util::base16_encode(pkey.prime2.as_vector()));
    FUNTLS_ASSERT_EQUAL(test_pkey0_e1, util::base16_encode(pkey.exponent1.as_vector()));
    FUNTLS_ASSERT_EQUAL(test_pkey0_e2, util::base16_encode(pkey.exponent2.as_vector()));
    FUNTLS_ASSERT_EQUAL(test_pkey0_c, util::base16_encode(pkey.coefficient.as_vector()));
}

int main()
{
    // TODO: Check x509::name equals operations. Only exact matches should be allowed (with order being important) etc.
    test_cert();
    test_pkey();
}
