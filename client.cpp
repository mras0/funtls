#include "tls_fetch.h"
#include <iostream>

#include <util/test.h>
#include <util/ostream_adapter.h>

using namespace funtls;

int main(int argc, char* argv[])
{
    try {
        if (argc < 2) {
            std::cout << "Usage: " << argv[0] << " https-uri [cipher...]\n";
            return 0;
        }

        // Lame URI parsing
        std::string uri(argv[1]);
        const auto expected_scheme = std::string("https://");
        FUNTLS_CHECK_BINARY(expected_scheme, ==, uri.substr(0, expected_scheme.size()), "Invalid HTTPS-URI: '" + uri + "'");
        uri = uri.substr(expected_scheme.size());

        std::string full_host, path;
        auto end_of_host = uri.find_first_of('/');
        if (end_of_host != std::string::npos) {
            full_host = uri.substr(0, end_of_host);
            path = uri.substr(end_of_host);
        } else {
            full_host = uri;
            path = "/";
        }
        std::string port = "443";
        std::string host = full_host;
        const auto colon_pos = host.find_first_of(':');
        if (colon_pos != std::string::npos) {
            host = full_host.substr(0, colon_pos);
            port = full_host.substr(colon_pos+1);
        }

        std::cout << "host: " << host << ":" << port << std::endl;
        std::cout << "path: " << path << std::endl;

        std::vector<tls::cipher_suite> wanted_ciphers{
            tls::cipher_suite::ecdhe_ecdsa_with_aes_256_gcm_sha384,
            tls::cipher_suite::ecdhe_ecdsa_with_aes_128_gcm_sha256,
            tls::cipher_suite::ecdhe_rsa_with_aes_256_gcm_sha384,
            tls::cipher_suite::ecdhe_rsa_with_aes_128_gcm_sha256,
            tls::cipher_suite::rsa_with_aes_256_gcm_sha384,
            tls::cipher_suite::rsa_with_aes_128_gcm_sha256,
            tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha256,
            tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha256,
            tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha,
            tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha,
            tls::cipher_suite::rsa_with_aes_256_cbc_sha256,
            tls::cipher_suite::rsa_with_aes_128_cbc_sha256,
            tls::cipher_suite::rsa_with_aes_256_cbc_sha,
            tls::cipher_suite::rsa_with_aes_128_cbc_sha,
            tls::cipher_suite::dhe_rsa_with_3des_ede_cbc_sha,
            tls::cipher_suite::rsa_with_3des_ede_cbc_sha,
            tls::cipher_suite::rsa_with_rc4_128_sha,
            tls::cipher_suite::rsa_with_rc4_128_md5,
        };
        if (argc > 2) {
            wanted_ciphers.clear();
            for (int arg = 2; arg < argc; ++arg) {
                std::string wanted_cipher_txt = argv[arg];
                tls::cipher_suite wanted_cipher = tls::cipher_suite::null_with_null_null;
                FUNTLS_CHECK_BINARY(bool(std::istringstream(wanted_cipher_txt)>>wanted_cipher), !=, false, "Invalid cipher " + wanted_cipher_txt);
                FUNTLS_CHECK_BINARY(wanted_cipher, !=, tls::cipher_suite::null_with_null_null, "Invalid cipher " + wanted_cipher_txt);
                wanted_ciphers.push_back(wanted_cipher);
            }
        }

        x509::trust_store ts;
        ts.set_log(std::cout);
        ts.add_os_defaults();

        util::ostream_adapter fetch_log{[](const std::string& s) { std::cout << "client: " << s; }};
        tls_fetch(host, port, path, wanted_ciphers, ts, [](const std::vector<uint8_t>& data) { 
            std::cout << std::string(data.begin(), data.end()) << std::flush;
        }, fetch_log);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
    }
    return 1;
}