#include <tls/tls.h>
#include <util/base_conversion.h>
#include <util/test.h>
#include <iostream>
#include <iomanip>

using namespace funtls;

int main()
{
    const auto secret = util::base16_decode("01234567");
    const auto seed   = util::base16_decode("89ABCDEF");
    FUNTLS_ASSERT_EQUAL("3E8464579C39D7334B5E0412A46125C848009EAEC8315139C5A965ADFDBD579FF8B1730AB8541457",
            util::base16_encode(tls::P_hash(secret,seed,40)));

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
        FUNTLS_ASSERT_EQUAL(0,                                  csp.iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::null,           csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.mac_length);
        FUNTLS_ASSERT_EQUAL(0,                                  csp.mac_key_length);
    }
    {
        const auto suite = tls::cipher_suite::rsa_with_aes_128_cbc_sha;
        const auto csp   = tls::parameters_from_suite(suite);
        std::cout << csp << std::endl;

        FUNTLS_ASSERT_EQUAL(suite,                              csp.cipher_suite);
        FUNTLS_ASSERT_EQUAL(tls::key_exchange_algorithm::rsa,   csp.key_exchange_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::prf_algorithm::tls_prf_sha256, csp.prf_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::bulk_cipher_algorithm::aes,    csp.bulk_cipher_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::cipher_type::block,            csp.cipher_type);
        FUNTLS_ASSERT_EQUAL(128/8,                              csp.key_length);
        FUNTLS_ASSERT_EQUAL(128/8,                              csp.block_length);
        FUNTLS_ASSERT_EQUAL(128/8,                              csp.iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::hmac_sha1,      csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(160/8,                              csp.mac_length);
        FUNTLS_ASSERT_EQUAL(160/8,                              csp.mac_key_length);
    }
    {
        const auto suite = tls::cipher_suite::rsa_with_aes_256_cbc_sha256;
        const auto csp   = tls::parameters_from_suite(suite);
        std::cout << csp << std::endl;

        FUNTLS_ASSERT_EQUAL(suite,                              csp.cipher_suite);
        FUNTLS_ASSERT_EQUAL(tls::key_exchange_algorithm::rsa,   csp.key_exchange_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::prf_algorithm::tls_prf_sha256, csp.prf_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::bulk_cipher_algorithm::aes,    csp.bulk_cipher_algorithm);
        FUNTLS_ASSERT_EQUAL(tls::cipher_type::block,            csp.cipher_type);
        FUNTLS_ASSERT_EQUAL(256/8,                              csp.key_length);
        FUNTLS_ASSERT_EQUAL(128/8,                              csp.block_length);
        FUNTLS_ASSERT_EQUAL(128/8,                              csp.iv_length);
        FUNTLS_ASSERT_EQUAL(tls::mac_algorithm::hmac_sha256,    csp.mac_algorithm);
        FUNTLS_ASSERT_EQUAL(256/8,                              csp.mac_length);
        FUNTLS_ASSERT_EQUAL(256/8,                              csp.mac_key_length);
    }
}
