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

std::pair<tls::content_type, std::vector<uint8_t>> read_record(boost::asio::ip::tcp::socket& socket)
{
    std::vector<uint8_t> buffer(5);
    boost::asio::read(socket, boost::asio::buffer(buffer));

    tls::record record;
    size_t index = 0;
    tls::from_bytes(record, buffer, index);
    assert(index == buffer.size());

    if (record.protocol_version != tls::protocol_version_tls_1_2) {
        throw std::runtime_error("Invalid record protocol version " + hexstring(&record.protocol_version, sizeof(record.protocol_version)) + " in " + __func__);
    }
    const size_t max_length = (1<<14)-1;
    if (record.length < 1 || record.length > max_length) {
        throw std::runtime_error("Invalid record length " + std::to_string(record.length) + " in " + __func__);
    }
    buffer.resize(record.length);
    boost::asio::read(socket, boost::asio::buffer(buffer));

    return std::make_pair(record.content_type, std::move(buffer));
}

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

void HandleServerHello(boost::asio::ip::tcp::socket& socket)
{
    auto handshake = read_handshake(socket);
    tls::server_hello server_hello;
    size_t index = 0;
    tls::from_bytes(server_hello, handshake.second, index);
    assert(index == handshake.second.size());
    if (handshake.first != tls::handshake_type::server_hello) {
        throw std::runtime_error("Invalid handshake type " + hexstring(&handshake.first, sizeof(handshake.first)) + " in " + __func__);
    }
    std::cout << "Cipher: "      << hexstring(&server_hello.cipher_suite, 2) << std::endl;
    std::cout << "Compresison: " << (int)server_hello.compression_method << std::endl;

    for (;;) {
        auto handshake = read_handshake(socket);
        std::cout << "Got handshake: " << hexstring(&handshake.first, sizeof(handshake.first)) << std::endl;
        if (handshake.first == tls::handshake_type::server_hello_done) break;
    }
}

void SendClientHello(boost::asio::ip::tcp::socket& socket)
{
    std::vector<uint8_t> body;
    tls::append_to_buffer(body, tls::client_hello{
        tls::protocol_version_tls_1_2,
        tls::make_random(),
        tls::make_session_id(),
        { tls::rsa_with_aes_256_cbc_sha256 },
        { tls::compression_method::null },
    });

    tls::handshake handshake{
        tls::handshake_type::client_hello,
        body.size(),
        tls::client_hello{
            tls::protocol_version_tls_1_2,
            tls::make_random(),
            tls::make_session_id(),
            { tls::rsa_with_aes_256_cbc_sha256 },
            { tls::compression_method::null },
        }
    };

    std::vector<uint8_t> buffer;
    tls::record record {
        tls::content_type::handshake,
        tls::protocol_version_tls_1_2,
        tls::uint<16>(body.size() + 4)
    };
    tls::append_to_buffer(buffer, record);
    assert(buffer.size() == 5);
    // Handshake header
    buffer.push_back(static_cast<uint8_t>(tls::handshake_type::client_hello));
    tls::append_to_buffer(buffer, tls::uint<24>(body.size()));
    buffer.insert(buffer.end(), body.begin(), body.end());
    assert(buffer.size() == 5 + 4 + body.size());
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
