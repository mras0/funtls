#include <iostream>
#include <boost/asio.hpp>
#include <util/test.h>
#include <util/ostream_adapter.h>
#include "server_test_utils.h"
#include "https_fetch.h"

using namespace funtls;

void self_test(boost::asio::io_service& io_service, uint16_t port)
{
    x509::trust_store ts;

    const std::vector<tls::cipher_suite> cipher_suites{
        //tls::cipher_suite::ecdhe_ecdsa_with_aes_256_gcm_sha384,
        //tls::cipher_suite::ecdhe_ecdsa_with_aes_128_gcm_sha256,

        tls::cipher_suite::ecdhe_rsa_with_aes_256_cbc_sha,
        tls::cipher_suite::ecdhe_rsa_with_aes_128_cbc_sha,

        tls::cipher_suite::ecdhe_rsa_with_aes_256_gcm_sha384,
        tls::cipher_suite::ecdhe_rsa_with_aes_128_gcm_sha256,

        tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha256,
        tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha256,
        tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha,
        tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha,
        tls::cipher_suite::dhe_rsa_with_3des_ede_cbc_sha,

        tls::cipher_suite::rsa_with_aes_256_gcm_sha384,
        tls::cipher_suite::rsa_with_aes_128_gcm_sha256,
        tls::cipher_suite::rsa_with_aes_256_cbc_sha256,
        tls::cipher_suite::rsa_with_aes_128_cbc_sha256,
        tls::cipher_suite::rsa_with_aes_256_cbc_sha,
        tls::cipher_suite::rsa_with_aes_128_cbc_sha,
        tls::cipher_suite::rsa_with_3des_ede_cbc_sha,
        tls::cipher_suite::rsa_with_rc4_128_sha,
        tls::cipher_suite::rsa_with_rc4_128_md5,
    };

    for (const auto& cs: cipher_suites) {
        io_service.post([cs] { std::cout << "=== Testing " << cs << " ===" << std::endl; });
        std::string res;
        util::ostream_adapter fetch_log{[&io_service](const std::string& s) { io_service.post([s] { std::cout << "Client: " << s; }); }};
        https_fetch("localhost", std::to_string(port), "/", {cs}, ts, [&res](const std::vector<uint8_t>& data) {
            res.insert(res.end(), data.begin(), data.end());
        }, fetch_log);

        // Make sure we synchronize with the main thread before proceeding to the next test
        sync_flag_provider provider;
        auto observer = provider.get_observer();
        io_service.post([res, &provider] {
            auto p = std::move(provider);
            std::cout << "Got result: \"" << res << "\"" << std::endl;
            FUNTLS_ASSERT_EQUAL(generic_reply, res);
            p.signal();
        });
        observer();
    }
}

int main()
{
    return server_test_main(&self_test);
}