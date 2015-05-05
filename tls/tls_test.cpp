#include <tls/tls.h>
#include <util/base_conversion.h>
#include <util/test.h>
#include <iostream>
#include <iomanip>

using namespace funtls;

void test_cipher_traits()
{
    {
        const auto suite = tls::cipher_suite::null_with_null_null;
        const auto csp   = tls::parameters_from_suite(suite);
        std::cout << csp << std::endl;

        FUNTLS_ASSERT_EQUAL(suite,                              csp.cipher_suite);
        FUNTLS_ASSERT_EQUAL(tls::key_exchange_algorithm::null,  csp.key_exchange_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::prf_algorithm::tls_prf_sha256, csp.prf_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::bulk_cipher_algorithm::null,   csp.bulk_cipher_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::cipher_type::stream,           csp.cipher_type);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.key_length);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.block_length);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.fixed_iv_length);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.record_iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::null,           csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.mac_length);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.mac_key_length);
    }
    {
        const auto suite = tls::cipher_suite::rsa_with_rc4_128_sha;
        const auto csp   = tls::parameters_from_suite(suite);
        std::cout << csp << std::endl;

        FUNTLS_ASSERT_EQUAL(suite,                              csp.cipher_suite);
        FUNTLS_ASSERT_EQUAL(tls::key_exchange_algorithm::rsa,   csp.key_exchange_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::prf_algorithm::tls_prf_sha256, csp.prf_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::bulk_cipher_algorithm::rc4,    csp.bulk_cipher_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::cipher_type::stream,           csp.cipher_type);
        FUNTLS_ASSERT_EQUAL(16,                                 csp.key_length);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.block_length);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.fixed_iv_length);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.record_iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::hmac_sha1,      csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(20,                                 csp.mac_length);
        FUNTLS_ASSERT_EQUAL(20,                                 csp.mac_key_length);
    }
    {
        const auto suite = tls::cipher_suite::rsa_with_aes_128_cbc_sha;
        const auto csp   = tls::parameters_from_suite(suite);
        std::cout << csp << std::endl;

        FUNTLS_ASSERT_EQUAL(suite,                               csp.cipher_suite);
        FUNTLS_ASSERT_EQUAL(tls::key_exchange_algorithm::rsa,    csp.key_exchange_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::prf_algorithm::tls_prf_sha256,  csp.prf_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::bulk_cipher_algorithm::aes_cbc, csp.bulk_cipher_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::cipher_type::block,             csp.cipher_type);
        FUNTLS_ASSERT_EQUAL(128/8,                               csp.key_length);
        FUNTLS_ASSERT_EQUAL(128/8,                               csp.block_length);
        FUNTLS_ASSERT_EQUAL(0,                                   csp.fixed_iv_length);
        FUNTLS_ASSERT_EQUAL(128/8,                               csp.record_iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::hmac_sha1,       csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(160/8,                               csp.mac_length);
        FUNTLS_ASSERT_EQUAL(160/8,                               csp.mac_key_length);
    }
    {
        const auto suite = tls::cipher_suite::rsa_with_aes_256_cbc_sha256;
        const auto csp   = tls::parameters_from_suite(suite);
        std::cout << csp << std::endl;

        FUNTLS_ASSERT_EQUAL(suite,                               csp.cipher_suite);
        FUNTLS_ASSERT_EQUAL(tls::key_exchange_algorithm::rsa,    csp.key_exchange_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::prf_algorithm::tls_prf_sha256,  csp.prf_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::bulk_cipher_algorithm::aes_cbc, csp.bulk_cipher_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::cipher_type::block,             csp.cipher_type);
        FUNTLS_ASSERT_EQUAL(256/8,                               csp.key_length);
        FUNTLS_ASSERT_EQUAL(128/8,                               csp.block_length);
        FUNTLS_ASSERT_EQUAL(0,                                   csp.fixed_iv_length);
        FUNTLS_ASSERT_EQUAL(128/8,                               csp.record_iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::hmac_sha256,     csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(256/8,                               csp.mac_length);
        FUNTLS_ASSERT_EQUAL(256/8,                               csp.mac_key_length);
    }
    {
        const auto suite = tls::cipher_suite::rsa_with_aes_128_gcm_sha256;
        const auto csp   = tls::parameters_from_suite(suite);
        std::cout << csp << std::endl;

        FUNTLS_ASSERT_EQUAL(suite,                               csp.cipher_suite);
        FUNTLS_ASSERT_EQUAL(tls::key_exchange_algorithm::rsa,    csp.key_exchange_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::prf_algorithm::tls_prf_sha256,  csp.prf_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::bulk_cipher_algorithm::aes_gcm, csp.bulk_cipher_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::cipher_type::aead,              csp.cipher_type);
        FUNTLS_ASSERT_EQUAL(128/8,                               csp.key_length);
        FUNTLS_ASSERT_EQUAL(128/8,                               csp.block_length);
        FUNTLS_ASSERT_EQUAL(4,                                   csp.fixed_iv_length);
        FUNTLS_ASSERT_EQUAL(8,                                   csp.record_iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::hmac_sha256,     csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(256/8,                               csp.mac_length);
        FUNTLS_ASSERT_EQUAL(0,                                   csp.mac_key_length);
    }
    {
        const auto suite = tls::cipher_suite::ecdhe_ecdsa_with_aes_128_gcm_sha256;
        const auto csp   = tls::parameters_from_suite(suite);
        std::cout << csp << std::endl;

        FUNTLS_ASSERT_EQUAL(suite,                                    csp.cipher_suite);
        FUNTLS_ASSERT_EQUAL(tls::key_exchange_algorithm::ecdhe_ecdsa, csp.key_exchange_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::prf_algorithm::tls_prf_sha256,       csp.prf_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::bulk_cipher_algorithm::aes_gcm,      csp.bulk_cipher_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::cipher_type::aead,                   csp.cipher_type);
        FUNTLS_ASSERT_EQUAL(128/8,                                    csp.key_length);
        FUNTLS_ASSERT_EQUAL(128/8,                                    csp.block_length);
        FUNTLS_ASSERT_EQUAL(4,                                        csp.fixed_iv_length);
        FUNTLS_ASSERT_EQUAL(8,                                        csp.record_iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::hmac_sha256,          csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(256/8,                                    csp.mac_length);
        FUNTLS_ASSERT_EQUAL(0,                                        csp.mac_key_length);
    }
}

void test_cipher_parsing()
{
    using namespace tls;
#define TEST_IN(expected, text) do {\
    std::istringstream iss(text);\
    tls::cipher_suite cs;\
    FUNTLS_ASSERT_EQUAL(true, bool(iss >> cs));\
    FUNTLS_ASSERT_EQUAL(cipher_suite::expected, cs);\
} while (0)
    TEST_IN(rsa_with_rc4_128_md5,                "rsa_with_rc4_128_md5");
    TEST_IN(rsa_with_rc4_128_sha,                "rsa_with_rc4_128_sha");
    TEST_IN(rsa_with_3des_ede_cbc_sha,           "rsa_with_3des_ede_cbc_sha");
    TEST_IN(rsa_with_aes_128_cbc_sha,            "rsa_with_aes_128_cbc_sha");
    TEST_IN(rsa_with_aes_128_cbc_sha256,         "rsa_with_aes_128_cbc_sha256");
    TEST_IN(rsa_with_aes_256_cbc_sha,            "rsa_with_aes_256_cbc_sha");
    TEST_IN(rsa_with_aes_256_cbc_sha256,         "rsa_with_aes_256_cbc_sha256");
    TEST_IN(dhe_rsa_with_3des_ede_cbc_sha,       "dhe_rsa_with_3des_ede_cbc_sha");
    TEST_IN(dhe_rsa_with_3des_ede_cbc_sha,       "dhe_rsa_with_3des_ede_cbc_sha");
    TEST_IN(dhe_rsa_with_aes_256_cbc_sha256,     "dhe_rsa_with_aes_256_cbc_sha256");
    TEST_IN(dhe_rsa_with_aes_128_cbc_sha,        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
    TEST_IN(dhe_rsa_with_aes_256_cbc_sha,        "DHE-RSA-AES256-sha");
    TEST_IN(rsa_with_aes_256_cbc_sha256,         "aes256-SHA256");
    TEST_IN(rsa_with_aes_128_gcm_sha256,         "AES128-GCM-SHA256");
    TEST_IN(ecdhe_ecdsa_with_aes_128_gcm_sha256, "ECDHE-ECDSA-AES128-GCM-SHA256");
#undef TEST_IN
}

int main()
{
    const auto secret = util::base16_decode("01234567");
    const auto seed   = util::base16_decode("89ABCDEF");
    FUNTLS_ASSERT_EQUAL("3E8464579C39D7334B5E0412A46125C848009EAEC8315139C5A965ADFDBD579FF8B1730AB8541457",
            util::base16_encode(tls::P_hash(secret,seed,40)));

    FUNTLS_ASSERT_EQUAL("0123456789ABCDEF1403030002",
            util::base16_encode(tls::verification_buffer(0x0123456789ABCDEF, tls::content_type::change_cipher_spec, tls::protocol_version_tls_1_2, 2)));

    test_cipher_traits();
    test_cipher_parsing();

}
