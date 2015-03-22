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

class tls_socket {
public:
    explicit tls_socket(boost::asio::ip::tcp::socket& socket)
        : socket(socket)
        , our_random(tls::make_random()) {
    }

    void perform_handshake() {
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

        send_client_hello();
        read_server_hello();
        read_until_server_hello_done();

        send_client_key_exchange();

        std::cout << "Session " << hexstring(sesion_id.as_vector()) << " in progress\n";
    }

private:
    const tls::protocol_version current_protocol_version = tls::protocol_version_tls_1_2;
    const tls::cipher_suite     wanted_cipher            = tls::rsa_with_aes_256_cbc_sha256;

    boost::asio::ip::tcp::socket& socket;
    const tls::random             our_random;
    tls::random                   their_random;
    tls::certificate              their_certificate;
    tls::session_id               sesion_id;

    template<typename Payload>
    void send_record(Payload&& payload) {
        std::vector<uint8_t> buffer;
        tls::append_to_buffer(buffer,
            tls::record{
                current_protocol_version,
                std::forward<Payload>(payload)
            });
        boost::asio::write(socket, boost::asio::buffer(buffer));
    }

    tls::record read_record() {
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

        if (protocol_version != current_protocol_version) {
            throw std::runtime_error("Invalid record protocol version " + hexstring(&protocol_version, sizeof(protocol_version)) + " in " + __func__);
        }
        if (length < 1 || length > tls::record::max_length) {
            throw std::runtime_error("Invalid record length " + std::to_string(length) + " in " + __func__);
        }
        buffer.resize(length);
        boost::asio::read(socket, boost::asio::buffer(buffer));
        index = 0;

        switch (content_type) {
        case tls::content_type::change_cipher_spec:
            break;
        case tls::content_type::alert:
            break;
        case tls::content_type::handshake:
            return tls::record{protocol_version, tls::handshake_from_bytes(buffer, index)};
        case tls::content_type::application_data:
            break;
        }
        throw std::runtime_error("Unknown content type " + std::to_string((int)content_type));
    }

    void send_client_hello() {
        send_record(
        tls::handshake{
            tls::client_hello{
                current_protocol_version,
                our_random,
                sesion_id,
                { wanted_cipher },
                { tls::compression_method::null },
            }
        });
    }

    void read_server_hello() {
        auto record = read_record();
        auto& server_hello = record.payload.get<tls::handshake>().body.get<tls::server_hello>();
        if (server_hello.cipher_suite != wanted_cipher) {
            throw std::runtime_error("Invalid cipher suite " + hexstring(&server_hello.cipher_suite, 2));
        }
        if (server_hello.compression_method != tls::compression_method::null) {
            throw std::runtime_error("Invalid compression method " + std::to_string((int)server_hello.compression_method));
        }
        their_random = server_hello.random;
        sesion_id = server_hello.session_id;
    }

    void read_until_server_hello_done() {
        std::vector<tls::certificate> certificate_lists;

        for (;;) {
            auto record = read_record();
            auto& handshake = record.payload.get<tls::handshake>();
            if (handshake.type() == tls::handshake_type::server_hello_done) {
                break;
            } else if (handshake.type() == tls::handshake_type::certificate) {
                // TODO: Only accept if before other type
                certificate_lists.push_back(std::move(handshake.body.get<tls::certificate>()));
            } else {
                throw std::runtime_error("Unknown handshake type " + std::to_string((int)handshake.type()));
            }
        }

        if (certificate_lists.size() != 1) {
            throw std::runtime_error("Unsupported number of certificate lists" + std::to_string(certificate_lists.size()));
        }
        if (certificate_lists[0].certificate_list.size() != 1) {
            throw std::runtime_error("Unsupported number of certificate lists" + std::to_string(certificate_lists[0].certificate_list.size()));
        }

        their_certificate = certificate_lists[0];
    }

    void send_client_key_exchange() {
        // OK, now it's time to do ClientKeyExchange
        // Since we're doing RSA, we'll be sending the EncryptedPreMasterSecret

        /*
   If RSA is being used for key agreement and authentication, the
      client generates a 48-byte premaster secret, encrypts it using the
      public key from the server's certificate, and sends the result in
      an encrypted premaster secret message.  This structure is a
      variant of the ClientKeyExchange message and is not a message in
      itself.

   Structure of this message:

      struct {
          ProtocolVersion client_version;
          opaque random[46];
      } PreMasterSecret;

      client_version
         The latest (newest) version supported by the client.  This is
         used to detect version rollback attacks.

      random
         46 securely-generated random bytes.

      struct {
          public-key-encrypted PreMasterSecret pre_master_secret;
      } EncryptedPreMasterSecret;
        */

        tls::client_key_exchange client_key_exchange;
        send_record(tls::handshake{client_key_exchange});
    }
};

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
        tls_socket ts{socket};
        ts.perform_handshake();

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Caught unknown exception" << std::endl;
        return 1;
    }
    return 0;
}
