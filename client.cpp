#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

#include <util/test.h>
#include <tls/tls_client.h>
#include <x509/trust_store.h>

#include <boost/asio.hpp>

using namespace funtls;

namespace {

std::exception_ptr make_exception(boost::system::error_code ec)
{
    return std::make_exception_ptr(boost::system::system_error(ec));
}

template<typename S>
class tls_stream : public tls::stream {
public:
    explicit tls_stream(S&& s) : s_(std::move(s)) {
    }

private:
    S s_;

    virtual void do_read(std::vector<uint8_t>& buf, const tls::done_handler& handler) override {
        async_read(s_, boost::asio::buffer(buf), [this, handler](const boost::system::error_code& ec, size_t) {
                    if (ec) {
                        handler(make_exception(ec));
                    } else {
                        handler(util::async_result<void>());
                    }
                });
    }

    virtual void do_write(const std::vector<uint8_t>& buf, const tls::done_handler& handler) override {
        async_write(s_, boost::asio::buffer(buf), [this, handler](const boost::system::error_code& ec, size_t) {
                    if (ec) {
                        handler(make_exception(ec));
                    } else {
                        handler(util::async_result<void>());
                    }
                });
    }
};

template<typename S>
std::unique_ptr<tls::stream> make_tls_stream(S&& s)
{
    return std::unique_ptr<tls::stream>(new tls_stream<S>(std::move(s)));
}

} // unnamed namespace

int main(int argc, char* argv[])
{
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
    FUNTLS_CHECK_BINARY(wanted_ciphers.size(), !=, 0, "No ciphers");

    x509::trust_store ts;
    //ts.add_from_directory("/etc/ssl/certs");
    ts.add_all_from_file("/etc/ssl/certs/ca-certificates.crt");

    boost::asio::io_service         io_service;
    boost::asio::ip::tcp::socket    socket(io_service);
    boost::asio::ip::tcp::resolver  resolver(io_service);

    std::cout << "Connecting to " << host << ":" << port << " ..." << std::flush;
    boost::asio::connect(socket, resolver.resolve({host, port}));
    std::cout << " OK" << std::endl;
    tls::verify_certificate_chain_func cf = std::bind(&x509::trust_store::verify_cert_chain, ts, std::placeholders::_1);
    tls::client client{make_tls_stream(std::move(socket)), wanted_ciphers, cf};

    tls::app_data_handler got_app_data = [&] (util::async_result<std::vector<uint8_t>> res) {
        try {
            auto data = res.get();
            std::cout << std::string(data.begin(), data.end()) << std::flush;
            client.recv_app_data(got_app_data);
        } catch (const boost::system::system_error& e) {
            if (e.code() == boost::asio::error::eof) {
                std::cout << "Got EOF\n";
                io_service.stop();
                return;
            }
            throw;
        }
    };

    client.perform_handshake([&] (util::async_result<void> res) {
            res.get();
            std::cout << "Handshake done!\n";
            const auto data = "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n";
            client.send_app_data(std::vector<uint8_t>(data.begin(), data.end()), [&] (util::async_result<void> res) {
                    res.get();
                    client.recv_app_data(got_app_data);
                });
        });
    io_service.run();
    std::cout << "io service exiting\n";

    return 0;
}
