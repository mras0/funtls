#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cassert>
#include <iomanip>
#include <array>

#include <int_util/int.h>
#include <int_util/int_util.h>

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

void visit_asn1(std::ostream& os, const asn1::der_encoded_value& v, int level);

template<asn1::identifier::tag tag>
void visit_asn1_sequence(std::ostream& os, const asn1::der_encoded_value& v, int level)
{
    auto seq = asn1::container_view<tag>{v};
    while (seq.has_next()) {
        visit_asn1(os, seq.next(), level);
    }
}

void visit_asn1(std::ostream& os, const asn1::der_encoded_value& v, int level = 0)
{
    os << std::string(level*2, ' ') << v << std::endl;
    switch (static_cast<uint8_t>(v.id())) {
    case asn1::identifier::constructed_sequence:
        visit_asn1_sequence<asn1::identifier::constructed_sequence>(os, v, level+1);
        break;
    case asn1::identifier::constructed_set:
        visit_asn1_sequence<asn1::identifier::constructed_set>(os, v, level+1);
        break;
    }
}

void visit_asn1(std::ostream& os, const std::vector<uint8_t>& v, int level = 0)
{
    util::buffer_view view{v.data(), v.size()};
    visit_asn1(os, asn1::read_der_encoded_value(view), level);
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
    FUNTLS_ASSERT_EQUAL(large_uint("11259235216357634699"), cert0.tbs().serial_number.as<large_uint>());
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
    FUNTLS_ASSERT_EQUAL(large_uint("0x055556bcf25ea43535c3a40fd5ab4572"), cert3.tbs().serial_number.as<large_uint>());
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
    FUNTLS_ASSERT_EQUAL(x509::id_rsaEncryption, pki.algorithm.id());
    FUNTLS_ASSERT_EQUAL(true,                   pki.algorithm.null_parameters());

    auto pkey = x509::rsa_private_key_from_pki(pki);

#if 0
#define P(f) std::cout << #f << " " << std::hex << pkey.f.as<large_uint>() << std::endl
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

    const auto pub = x509::rsa_public_key::from_private(pkey);
    const std::vector<uint8_t> msg{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14 };
    const auto e1_msg = x509::pkcs1_encode(pkey, msg);
    auto di = x509::pkcs1_decode(pub, e1_msg);
    FUNTLS_ASSERT_EQUAL(x509::id_sha1, di.digest_algorithm().id());
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}), di.digest());

    const auto e2_msg = x509::pkcs1_encode(pub, msg);
    FUNTLS_ASSERT_EQUAL(msg, x509::pkcs1_decode(pkey, e2_msg));

    // Serialization
    FUNTLS_ASSERT_EQUAL(crude_get_pem_data(test_pkey0), asn1::serialized(pki));

    std::ostringstream pkey_pem;
    x509::write_pem_private_key_info(pkey_pem, pki);
    FUNTLS_ASSERT_EQUAL(test_pkey0, pkey_pem.str());
}

void test_pkey_generation()
{
    const auto pk = x509::rsa_private_key::generate(256);

    const auto n = pk.modulus.as<large_uint>();
    const auto e = pk.public_exponent.as<large_uint>();
    const auto d = pk.private_exponent.as<large_uint>();
    const auto p = pk.prime1.as<large_uint>();
    const auto q = pk.prime2.as<large_uint>();
    const auto e1 = pk.exponent1.as<large_uint>();
    const auto e2 = pk.exponent2.as<large_uint>();
    const auto coef = pk.coefficient.as<large_uint>();
    const auto bit_count = 8 * ilog256(n);

    FUNTLS_ASSERT_EQUAL(0, pk.version.as<int>());
    FUNTLS_ASSERT_EQUAL(256, bit_count);
    FUNTLS_ASSERT_EQUAL(true, is_prime(p));
    FUNTLS_ASSERT_EQUAL(true, is_prime(q));
    FUNTLS_ASSERT_EQUAL(n, large_uint{p * q});
    const large_uint phi_n = n - (p + q -1);
    FUNTLS_ASSERT_BINARY_MESSAGE(e, >=, 65537, ""); 
    FUNTLS_ASSERT_BINARY_MESSAGE(e, <, phi_n, "");
    FUNTLS_ASSERT_EQUAL(1, gcd(e, phi_n));
    FUNTLS_ASSERT_EQUAL(d, modular_inverse(e, phi_n));

    FUNTLS_ASSERT_EQUAL(e1, large_uint{d % (p-1)});
    FUNTLS_ASSERT_EQUAL(e2, large_uint{d % (q-1)});
    FUNTLS_ASSERT_EQUAL(coef, modular_inverse(q, p));

    // 2n**(1/4) for n = 2**256 = 2 * 18446744073709551616
    const large_uint n_pow_neg4_est("18446744073709551616");
    FUNTLS_ASSERT_BINARY_MESSAGE(large_uint{p > q ? p - q : q - p}, >, large_uint{2*n_pow_neg4_est}, "Primes are too close");

    FUNTLS_ASSERT_BINARY_MESSAGE(d, >, large_uint{n_pow_neg4_est / 3}, "Private key too small");

    // TODO: Better checking of the generated values
    // e.g. if either p ? 1 or q ? 1 has only small prime factors, n can be factored quickl
}


void test_serialization()
{
    //digest_info.insert(digest_info.begin(), {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14});
    // SHA1 algo info

    // AlgorithmIdentifier
    const std::vector<uint8_t> sha1_algo_id_no_params_bytes{0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a};
    util::buffer_view sha1_algo_id_buf{sha1_algo_id_no_params_bytes.data(), sha1_algo_id_no_params_bytes.size()};
    x509::algorithm_id sha1_algo_id_no_param{asn1::read_der_encoded_value(sha1_algo_id_buf)};
    FUNTLS_ASSERT_EQUAL(x509::id_sha1, sha1_algo_id_no_param.id());
    FUNTLS_ASSERT_EQUAL(true, sha1_algo_id_no_param.null_parameters());
    FUNTLS_ASSERT_EQUAL(0, sha1_algo_id_no_param.parameters().size());
    std::vector<uint8_t> sha1_algo_id_no_param_serialized;
    sha1_algo_id_no_param.serialize(sha1_algo_id_no_param_serialized);
    FUNTLS_ASSERT_EQUAL(sha1_algo_id_no_params_bytes, sha1_algo_id_no_param_serialized);

    const std::vector<uint8_t> sha1_algo_id_null_params_bytes{0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00};
    util::buffer_view sha1_algo_id_buf2{sha1_algo_id_null_params_bytes.data(), sha1_algo_id_null_params_bytes.size()};
    x509::algorithm_id sha1_algo_id_null_param{asn1::read_der_encoded_value(sha1_algo_id_buf2)};
    FUNTLS_ASSERT_EQUAL(x509::id_sha1, sha1_algo_id_null_param.id());
    FUNTLS_ASSERT_EQUAL(true, sha1_algo_id_null_param.null_parameters());
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x05, 0x00}), sha1_algo_id_null_param.parameters());
    std::vector<uint8_t> sha1_algo_id_null_param_serialized;
    sha1_algo_id_null_param.serialize(sha1_algo_id_null_param_serialized);
    FUNTLS_ASSERT_EQUAL(sha1_algo_id_null_params_bytes, sha1_algo_id_null_param_serialized);


    const std::vector<uint8_t> digest_info_bytes{
        0x30, 0x11,     // constructed sequence (DigestInfo)
            0x30, 0x09, // constructed sequence (digestAlgorithm)
                0x06, 0x05, // oid
                    0x2b, 0x0e, 0x03, 0x02, 0x1a, // 1.3.14.3.2.26
                0x05, 0x00, // null
                    // no data
            0x04, 0x4, // octet_string digest)
                1,2,3,4
    };
    util::buffer_view digest_info_buf{digest_info_bytes.data(), digest_info_bytes.size()};
    auto digest_info = x509::digest_info::parse(asn1::read_der_encoded_value(digest_info_buf));
    FUNTLS_ASSERT_EQUAL(x509::id_sha1, digest_info.digest_algorithm().id());
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x05, 0x00}), digest_info.digest_algorithm().parameters());
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04}), digest_info.digest());
    FUNTLS_ASSERT_EQUAL(digest_info_bytes, asn1::serialized(digest_info));

    // version
    {
        std::vector<uint8_t> expected_ver_buffer{0xA0, 0x03, 0x02, 0x01, 0x02};
        FUNTLS_ASSERT_EQUAL(expected_ver_buffer, asn1::serialized(x509::version{x509::version::v3}));
        util::buffer_view expected_ver_buffer_view(expected_ver_buffer.data(), expected_ver_buffer.size());
        FUNTLS_ASSERT_EQUAL(x509::version(asn1::read_der_encoded_value(expected_ver_buffer_view)), x509::version::v3);
    }

    {
        std::vector<uint8_t> common_name_localhost_bytes = util::base16_decode("30143112301006035504030C096C6F63616C686F7374");
        util::buffer_view common_name_localhost_view{common_name_localhost_bytes.data(), common_name_localhost_bytes.size()};
        const x509::name common_name_localhost{asn1::read_der_encoded_value(common_name_localhost_view)};
        const auto common_name_localhost_attr = common_name_localhost.attributes();
        FUNTLS_ASSERT_EQUAL(common_name_localhost_attr.size(), 1);
        FUNTLS_ASSERT_EQUAL(common_name_localhost_attr[0].first, x509::attr_commonName);
        FUNTLS_ASSERT_EQUAL(common_name_localhost_attr[0].second, asn1::utf8_string{"localhost"});
        FUNTLS_ASSERT_EQUAL(asn1::serialized(common_name_localhost), common_name_localhost_bytes);
    
        x509::name name{{std::make_pair(x509::attr_commonName, asn1::ia5_string{"Hello world"}),std::make_pair(x509::attr_countryName, asn1::ia5_string{"XQ"})}};
        const std::vector<uint8_t> expeced_name_bytes = util::base16_decode("3023311430120603550403160B48656C6C6F20776F726C64310B3009060355040616025851");
        FUNTLS_ASSERT_EQUAL(asn1::serialized(name), expeced_name_bytes);
        util::buffer_view name_view{expeced_name_bytes.data(), expeced_name_bytes.size()};
        FUNTLS_ASSERT_EQUAL(x509::name{asn1::read_der_encoded_value(name_view)} , name);
    }

    {
        x509::name subject{{std::make_pair(x509::attr_commonName, asn1::ia5_string{"localhost"})}};
        x509::name issuer{{std::make_pair(x509::attr_countryName, asn1::ia5_string{"foobar"})}};

        const asn1::utc_time not_before{"1511080000Z"};
        const asn1::utc_time not_after{"2511080000Z"};
        const asn1::bit_string subject_public_key{std::vector<uint8_t>{1,2,3}};

        x509::tbs_certificate tbs{
            x509::version::v3,                                    // version
            asn1::integer::from_bytes({0x01}),                    // serial_number
            x509::algorithm_id{x509::id_sha256WithRSAEncryption}, // signature_algorithm
            issuer,                                               // issuer
            not_before,                                           // validity_not_before
            not_after,                                            // validity_not_after
            subject,                                              // subect
            x509::algorithm_id{x509::id_rsaEncryption},           // subject_public_key_algo
            subject_public_key,                                   // subject_public_key
            {} // extensions
        };

        const auto tbs_bytes = asn1::serialized(tbs);
        util::buffer_view view{tbs_bytes.data(), tbs_bytes.size()};
        auto read_tbs = x509::parse_tbs_certificate(asn1::read_der_encoded_value(view));

        FUNTLS_ASSERT_EQUAL(x509::version::v3, read_tbs.version);
        FUNTLS_ASSERT_EQUAL(1, read_tbs.serial_number.as<int>());
        FUNTLS_ASSERT_EQUAL(x509::id_sha256WithRSAEncryption, read_tbs.signature_algorithm.id());
        FUNTLS_ASSERT_EQUAL(true, read_tbs.signature_algorithm.null_parameters());
        FUNTLS_ASSERT_EQUAL(subject, read_tbs.subject);
        FUNTLS_ASSERT_EQUAL(not_before.as_string(), read_tbs.validity_not_before.as_string());
        FUNTLS_ASSERT_EQUAL(not_after.as_string(), read_tbs.validity_not_after.as_string());
        FUNTLS_ASSERT_EQUAL(issuer, read_tbs.issuer);
        FUNTLS_ASSERT_EQUAL(x509::id_rsaEncryption, read_tbs.subject_public_key_algo.id());
        FUNTLS_ASSERT_EQUAL(true, read_tbs.subject_public_key_algo.null_parameters());
        FUNTLS_ASSERT_EQUAL(true, read_tbs.extensions.empty());

        const char* const certs[] = {
            test_cert0,
            test_cert1,
            // test_cert2, // x509v1 certificate - not supported
            test_cert3,
            test_cert_chain0_root
        };

        for (auto pem_data : certs) {
            const auto cert = x509::read_pem_certificate_from_string(pem_data);

            const auto tbs_serialized = asn1::serialized(cert.tbs());
            // Can the serialized data be re-read
            util::buffer_view tbs_serialized_view{tbs_serialized.data(), tbs_serialized.size()};
            const auto reread_tbs = x509::parse_tbs_certificate(asn1::read_der_encoded_value(tbs_serialized_view));

            FUNTLS_ASSERT_EQUAL(cert.tbs().version, reread_tbs.version);
            FUNTLS_ASSERT_EQUAL(cert.tbs().serial_number.as_vector(), reread_tbs.serial_number.as_vector());
            FUNTLS_ASSERT_EQUAL(cert.tbs().signature_algorithm.id(), reread_tbs.signature_algorithm.id());
            FUNTLS_ASSERT_EQUAL(cert.tbs().signature_algorithm.null_parameters(), reread_tbs.signature_algorithm.null_parameters());
            FUNTLS_ASSERT_EQUAL(cert.tbs().subject, reread_tbs.subject);
            FUNTLS_ASSERT_EQUAL(cert.tbs().validity_not_before.as_string(), reread_tbs.validity_not_before.as_string());
            FUNTLS_ASSERT_EQUAL(cert.tbs().validity_not_after.as_string(), reread_tbs.validity_not_after.as_string());
            FUNTLS_ASSERT_EQUAL(cert.tbs().issuer, reread_tbs.issuer);
            FUNTLS_ASSERT_EQUAL(cert.tbs().subject_public_key_algo.id(), reread_tbs.subject_public_key_algo.id());
            FUNTLS_ASSERT_EQUAL(cert.tbs().subject_public_key_algo.null_parameters(), reread_tbs.subject_public_key_algo.null_parameters());
            FUNTLS_ASSERT_EQUAL(cert.tbs().extensions.size(), reread_tbs.extensions.size());
            for (size_t i = 0; i < reread_tbs.extensions.size(); ++i) {
                const auto& a = cert.tbs().extensions[i];
                const auto& b = reread_tbs.extensions[i];
                FUNTLS_ASSERT_EQUAL(a.id, b.id);
                FUNTLS_ASSERT_EQUAL(a.critical_present, b.critical_present);
                FUNTLS_ASSERT_EQUAL(a.critical, b.critical);
                FUNTLS_ASSERT_EQUAL(a.value, b.value);
            }

            // Can we serialize the tbs_certificate and get it back exactly?

            //auto a = cert.certificate_der_encoded();
            //util::buffer_view av{a.data(), a.size()};
            //std::ofstream atxt("c:/temp/a.txt");
            //atxt << cert << "\n\n";
            //visit_asn1(atxt, asn1::read_der_encoded_value(av));
            //auto b = tbs_serialized;
            //util::buffer_view bv{b.data(), b.size()};
            //std::ofstream btxt("c:/temp/b.txt");
            //btxt << reread_tbs << "\n\n";
            //visit_asn1(btxt, asn1::read_der_encoded_value(bv));

            FUNTLS_ASSERT_EQUAL(cert.certificate_der_encoded(), tbs_serialized);

            // Serialize the complete certificate and check that it matches the input
            const auto cert_serialized = asn1::serialized(cert);
            // Read the certificate..
            util::buffer_view cert_ser_view{cert_serialized.data(), cert_serialized.size()};
            const auto reread_cert = x509::certificate::parse(asn1::read_der_encoded_value(cert_ser_view));
            FUNTLS_ASSERT_EQUAL(cert.certificate_der_encoded(), reread_cert.certificate_der_encoded());
            FUNTLS_ASSERT_EQUAL(cert.signature_algorithm().id(), reread_cert.signature_algorithm().id());
            FUNTLS_ASSERT_EQUAL(cert.signature_algorithm().parameters(), reread_cert.signature_algorithm().parameters());
            FUNTLS_ASSERT_EQUAL(cert.signature().as_vector(), reread_cert.signature().as_vector());

            // Finally check that we end up with the original PEM encoded data when re-encoding the certificate
            std::ostringstream oss;
            x509::write_pem_certificate(oss, cert_serialized);
            FUNTLS_ASSERT_EQUAL(pem_data, oss.str());
        }
    }
}

#include "test_cert4.h"
void test_cert_extensions()
{
    const auto cert4 = x509::read_pem_certificate_from_string(test_cert4);
    std::ostringstream cert4_subject_name, cert4_issuer_name;
    cert4_subject_name << cert4.tbs().subject;
    cert4_issuer_name << cert4.tbs().issuer;
    FUNTLS_ASSERT_EQUAL(large_uint("0x3f7d9a402f58b092"), cert4.tbs().serial_number.as<large_uint>());
    FUNTLS_ASSERT_EQUAL(cert4_subject_name.str(), "C=US, ST=California, L=Mountain View, O=Google Inc, CN=google.com");
    FUNTLS_ASSERT_EQUAL(cert4_issuer_name.str(), "C=US, O=Google Inc, CN=Google Internet Authority G2");
    FUNTLS_ASSERT_EQUAL(x509::id_sha256WithRSAEncryption, cert4.tbs().signature_algorithm.id());
    FUNTLS_ASSERT_EQUAL(true, cert4.tbs().signature_algorithm.null_parameters());
    FUNTLS_ASSERT_EQUAL(x509::id_rsaEncryption, cert4.tbs().subject_public_key_algo.id());
    FUNTLS_ASSERT_EQUAL(x509::id_sha256WithRSAEncryption, cert4.signature_algorithm().id());
    FUNTLS_ASSERT_EQUAL(true, cert4.signature_algorithm().null_parameters());
    test_load_save(test_cert4);

    //std::cout << cert4 << std::endl;
}

#include <x509/trust_store.h>
void test_trust_store()
{
    std::istringstream chain_iss(test_cert_chain0);
    const auto chain = read_pem_cert_chain(chain_iss);
    const auto root_cert = x509::read_pem_certificate_from_string(test_cert_chain0_root);

    x509::trust_store empty_ts;
    FUNTLS_ASSERT_THROWS(empty_ts.verify_cert_chain(chain), std::runtime_error);
    FUNTLS_ASSERT_THROWS(empty_ts.verify_cert_chain({root_cert}), std::runtime_error);

    x509::trust_store ts1;
    ts1.add(root_cert);
    ts1.verify_cert_chain(chain);
    ts1.verify_cert_chain({root_cert});

    // TODO: Improve negative tests, e.g. the case where a self-signed certificate for the subject
    // is found in the trust store, but we try to verify another certificate for the same subject
}

int main()
{
    // TODO: Check x509::name equals operations. Only exact matches should be allowed (with order being important) etc.
    try {
        test_cert();
        test_cert_extensions();
        test_pkey();
        test_pkey_generation();
        test_serialization();
        test_trust_store();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
