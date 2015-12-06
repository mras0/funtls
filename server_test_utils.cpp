#include "server_test_utils.h"
#include <thread>
#include <boost/asio/io_service.hpp>

#include <util/base_conversion.h>
#include <util/ostream_adapter.h>
#include <x509/x509_io.h>
#include <tls/tls_server_rsa_kex.h>
#include "tcp_tls_server.h"

#include <iostream>

using namespace funtls;

namespace {

std::unique_ptr<tls::server_id> get_server_test_id()
{
    static const char private_key[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIICLgIBADANBgkqhkiG9w0BAQEFAASCAhgwggIUAgEAAkEAlUQe0RtIgCXpD0lkH5lco\n"
        "pG/XrmJShcS462aLhucWEKjX5obKeHJ0NDEzpohGR/vZTTnYsABUp359WovMXD+ZQJAJQ\n"
        "3gZa4/3AQOrTrOZkk8xx583O3lkUPsuHqZ/lXOp5ipZrDWznK6EcoXVe9IJWzoIDVQdij\n"
        "ZuuBBIACXNkEPfwJAM45L/6COc4KaPqJlx6lgtDeVxrQtbxBdkTKO9G4ATsYFIno4fSgg\n"
        "jrd31dGpzgXHckrKWT9u4zsALa8yP1Ed5wJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "AAAAAAAAADAUalZCSgsIQZuInQ3I4L0LeqTuHh9etZE8ehcuBamhwJAAAAAAAAAAAAAAA\n"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAADGsPyBsTjUZ1jpPPsFwOi8eik2Tq7baHVG3AL69ya\n"
        "CswJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACc7dNb7PXFwvlW/9uSHzOs\n"
        "9oelPYpaRXldYRIRDJNG6wJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABhf\n"
        "qZJDN4j7pg/q/iUJDrhSP0Ru87iPcejoB0qA2sx5QJAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "AAAAAAAAAAAAAAAACdt2KWqpWDI9KyNS/jMho4UBocb4Ax3E/2TNRLMsRtwg==\n"
        "-----END PRIVATE KEY-----";
    static const char certificate[] =
        "MIIBUjCB/aADAgECAgEBMA0GCSqGSIb3DQEBBAUAMBQxEjAQBgNVBAMWCWxvY2Fs"
        "aG9zdDAaFwsxNTExMDgwMDAwWhcLMjUxMTA4MDAwMFowFDESMBAGA1UEAxYJbG9j"
        "YWxob3N0MIGbMA0GCSqGSIb3DQEBAQUAA4GJADCBhQJBAJVEHtEbSIAl6Q9JZB+Z"
        "XKKRv165iUoXEuOtmi4bnFhCo1+aGynhydDQxM6aIRkf72U052LAAVKd+fVqLzFw"
        "/mUCQCUN4GWuP9wEDq06zmZJPMcefNzt5ZFD7Lh6mf5VzqeYqWaw1s5yuhHKF1Xv"
        "SCVs6CA1UHYo2brgQSAAlzZBD38wDQYJKoZIhvcNAQEEBQADQQBMhEJLmCS0dkS8"
        "NKWutTJIaoON+jkLOnIXauB3f2XXQ5J+Bm8HquJHPGx4CGG/5SasJr/RBOzZN6Mv"
        "L3SPTuuT";

    auto pki = x509::read_pem_private_key_from_string(private_key);
    assert(pki.version.as<int>() == 0);
    assert(pki.algorithm.id() == x509::id_rsaEncryption);

    return tls::make_rsa_server_id({util::base64_decode(certificate, sizeof(certificate)-1)}, x509::rsa_private_key_from_pki(pki));
}

class client_thread {
public:
    using func_type = std::function<void (void)>;

    client_thread(boost::asio::io_service& io_service, const func_type& main) : io_service_(io_service), main_(main), thread_([this] { thread_func(); }) {
    }

    ~client_thread() {
        thread_.join();
    }

    void get() {
        if (exception_) {
            std::rethrow_exception(exception_);
        }
    }

private:
    boost::asio::io_service& io_service_;
    func_type                main_;
    std::exception_ptr       exception_;
    std::thread              thread_;

    void thread_func() {
        boost::asio::io_service::work work(io_service_); // keep the io_service running as long as the thread does

        try {
            main_();
        } catch (...) {
            exception_ = std::current_exception();
        }

        // Make sure we only capture the io_service
        boost::asio::io_service& io_service = io_service_;
        io_service.post([&io_service] { io_service.stop(); });
    }
};

std::shared_ptr<std::ostream> make_log(const std::string& name)
{
    return std::make_shared<util::ostream_adapter>([name](const std::string& s) { std::cout << name + ": " + s; });
}

void main_loop(util::async_result<std::shared_ptr<tls::tls_base>> async_self, std::shared_ptr<std::ostream> log)
{
    auto self = async_self.get();
    self->recv_app_data(
        [self, log](util::async_result<std::vector<uint8_t>> async_data) {
        const auto data = async_data.get();
        (*log) << "Got app data: " << std::string(data.begin(), data.end());
        self->send_app_data(std::vector<uint8_t>(generic_reply.begin(), generic_reply.end()), [self, log](util::async_result<void> res) {
            res.get();
            // self->main_loop();
        });
    });
}

} // unnamed namespace

namespace funtls {

const std::string generic_reply = "Content-type: text/ascii\r\n\r\nHello world!\r\n";

int server_test_main(const test_main_func_type& test_main)
{
    try {
        boost::asio::io_service  io_service;
        auto server  = tcp_tls_server::create(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0), get_server_test_id(), &make_log, &main_loop);

        std::cout << "Server running: " << server->local_endpoint() << std::endl;

        unsigned short port = server->local_endpoint().port();
        client_thread test_client{io_service, [&] {
            test_main(io_service, port);
        }};
        io_service.run();
        test_client.get();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
        return 1;
    }
    return 0;
}

} // namespace funtls