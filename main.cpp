#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <boost/asio.hpp>

#include "tls.h"
#include "tls_ciphers.h"

// http://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl
// openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
// cat server_key.pem server_cert.pem >server.pem
// openssl s_server

char hexchar(uint8_t d)
{
    assert(d < 16);
    return d < 10 ? d + '0' : d + 'a' - 10;
}

std::string hexstring(const void* buffer, size_t len)
{
    const uint8_t* bytes = static_cast<const uint8_t*>(buffer);
    assert(len <= len*2);
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += hexchar(bytes[i] >> 4);
        result += hexchar(bytes[i] & 0xf);
    }
    return result;
}

template<typename T>
std::string hexstring(const T& x)
{
    if (x.empty()) return "";
    return hexstring(&x[0], x.size() * sizeof(x[0]));
}

#if 0
std::pair<tls::handshake_type, std::vector<uint8_t>> read_handshake(boost::asio::ip::tcp::socket& socket)
{
    auto record = read_record(socket);
    if (record.first != tls::content_type::handshake) {
        throw std::runtime_error("Invalid record content type " + hexstring(&record.first, sizeof(record.first)) + " in " + __func__);
    }

    size_t index = 0;
    tls::handshake_type handshake_type;
    tls::uint<24> body_size;
    tls::from_bytes(handshake_type, record.second, index);
    tls::from_bytes(body_size, record.second, index);
    if (index + body_size > record.second.size()) {
        throw std::runtime_error("Invalid body size " + std::to_string(body_size));
    }
    return std::make_pair(handshake_type, std::vector<uint8_t>{record.second.begin() + index, record.second.end()});
}
#endif

tls::handshake parse_handshake(const std::vector<uint8_t>& buffer)
{
    size_t index = 0;
    tls::handshake_type handshake_type;
    tls::uint<24> body_size;
    tls::from_bytes(handshake_type, buffer, index);
    tls::from_bytes(body_size, buffer, index);
    if (index + body_size > buffer.size()) {
        throw std::runtime_error("Invalid body size " + std::to_string(body_size));
    }
    if (handshake_type == tls::handshake_type::server_hello) {
        tls::server_hello server_hello;
        tls::from_bytes(server_hello, buffer, index);
        assert(index == buffer.size());
        return tls::handshake{std::move(server_hello)};
    } else if (handshake_type == tls::handshake_type::certificate) {
        tls::certificate certificate;
        tls::from_bytes(certificate, buffer, index);
        assert(index == buffer.size());
        return tls::handshake{std::move(certificate)};
    } else if (handshake_type == tls::handshake_type::server_hello_done) {
        if (body_size != 0) {
            throw std::runtime_error("Got body " + std::to_string(body_size) + " for server_hello_done");
        }
        assert(index == buffer.size());
        return tls::handshake{tls::server_hello_done{}};
    }
    throw std::runtime_error("Unknown handshake type " + std::to_string((int)handshake_type));
 }

tls::record read_record(boost::asio::ip::tcp::socket& socket)
{
    std::vector<uint8_t> buffer(5);
    boost::asio::read(socket, boost::asio::buffer(buffer));

    size_t index = 0;
    tls::content_type     content_type;
    tls::protocol_version protocol_version;
    tls::uint<16>         length;
    tls::from_bytes(content_type, buffer, index);
    tls::from_bytes(protocol_version, buffer, index);
    tls::from_bytes(length, buffer, index);
    assert(index == buffer.size());

    if (protocol_version != tls::protocol_version_tls_1_2) {
        throw std::runtime_error("Invalid record protocol version " + hexstring(&protocol_version, sizeof(protocol_version)) + " in " + __func__);
    }
    if (length < 1 || length > tls::record::max_length) {
        throw std::runtime_error("Invalid record length " + std::to_string(length) + " in " + __func__);
    }
    buffer.resize(length);
    boost::asio::read(socket, boost::asio::buffer(buffer));

    switch (content_type) {
    case tls::content_type::change_cipher_spec:
    case tls::content_type::alert:
        break;
    case tls::content_type::handshake:
        return tls::record{protocol_version, parse_handshake(buffer)};
    case tls::content_type::application_data:
        break;
    }
    throw std::runtime_error("Unknown content type " + std::to_string((int)content_type));
}

void HandleServerHello(boost::asio::ip::tcp::socket& socket)
{
    auto record = read_record(socket);
    auto handshake = record.payload.get<tls::handshake>();
    auto server_hello = handshake.body.get<tls::server_hello>();
    std::cout << "Cipher: "      << hexstring(&server_hello.cipher_suite, 2) << std::endl;
    std::cout << "Compresison: " << (int)server_hello.compression_method << std::endl;

    for (;;) {
        auto record = read_record(socket);
        auto handshake = record.payload.get<tls::handshake>();
        std::cout << "Got handshake of type " << (unsigned)handshake.type() << std::endl;
        if (handshake.type() == tls::handshake_type::server_hello_done) break;
    }
}

void SendClientHello(boost::asio::ip::tcp::socket& socket)
{
    tls::record record{
        tls::protocol_version_tls_1_2,
        tls::handshake{
            tls::client_hello{
                tls::protocol_version_tls_1_2,
                tls::make_random(),
                tls::make_session_id(),
                { tls::rsa_with_aes_256_cbc_sha256 },
                { tls::compression_method::null },
            }
        }
    };

    std::vector<uint8_t> buffer;
    tls::append_to_buffer(buffer, record);
    boost::asio::write(socket, boost::asio::buffer(buffer));
}

int main()
{
    const char* const host = "localhost";
    const char* const port = "4433";

    try {
        boost::asio::io_service         io_service;
        boost::asio::ip::tcp::socket    socket(io_service);
        boost::asio::ip::tcp::resolver  resolver(io_service);

        std::cout << "Connecting to " << host << ":" << port << " ..." << std::flush;
        boost::asio::connect(socket, resolver.resolve({host, port}));
        std::cout << " OK" << std::endl;
        /*
        Client                                               Server

        ClientHello                  -------->
                                                        ServerHello
                                                       Certificate*
                                                 ServerKeyExchange*
                                                CertificateRequest*
                                     <--------      ServerHelloDone
        Certificate*
        ClientKeyExchange
        CertificateVerify*
        [ChangeCipherSpec]
        Finished                     -------->
                                                 [ChangeCipherSpec]
                                     <--------             Finished
        Application Data             <------->     Application Data
        */

        std::cout << "Sending ClientHello ..." << std::flush;
        SendClientHello(socket);
        std::cout << " OK" << std::endl;

        std::cout << "Handling ServerHello ..." << std::flush;
        HandleServerHello(socket);
        std::cout << " OK" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Caught unknown exception" << std::endl;
        return 1;
    }
    return 0;
}
