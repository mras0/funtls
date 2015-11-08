#include "tls_fetch.h"

#include <util/test.h>
#include <tls/tls_client.h>
#include <x509/trust_store.h>

#include <asio_stream_adapter.h>

namespace funtls {

void tls_fetch(const std::string& host, const std::string& port, const std::string& path, const std::vector<tls::cipher_suite>& wanted_ciphers, const x509::trust_store& ts, std::function<void (const std::vector<uint8_t>&)> on_data, std::ostream& log)
{
    FUNTLS_CHECK_BINARY(wanted_ciphers.size(), !=, 0, "No ciphers");

    boost::asio::io_service         io_service;
    boost::asio::ip::tcp::socket    socket(io_service);
    boost::asio::ip::tcp::resolver  resolver(io_service);

    log << "Connecting to " << host << ":" << port << " ..." << std::flush;
    boost::asio::connect(socket, resolver.resolve({host, port}));
    log << " OK" << std::endl;
    tls::verify_certificate_chain_func cf = std::bind(&x509::trust_store::verify_cert_chain, ts, std::placeholders::_1);
    tls::client client{make_tls_stream(std::move(socket)), wanted_ciphers, cf};

    tls::app_data_handler got_app_data = [&] (util::async_result<std::vector<uint8_t>> res) {
        try {
            auto data = res.get();
            on_data(data);
            client.recv_app_data(got_app_data);
        } catch (const boost::system::system_error& e) {
            if (e.code() == boost::asio::error::eof) {
                log << "Got EOF\n";
                io_service.stop();
                return;
            }
            throw;
        }
    };


    util::async_result<void> result;
    tls::done_handler handler = [&](util::async_result<void> res) {
        result = std::move(res);
    };

    client.perform_handshake(util::wrapped([&] {
        log << "Handshake done!\n";
        const auto data = "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n";
        client.send_app_data(std::vector<uint8_t>(data.begin(), data.end()), util::wrapped([&](){
            client.recv_app_data(got_app_data);
        }, handler));
    }, handler));
    io_service.run();
    log << "io service exiting\n";
    result.get();
}

} // namespace funtls