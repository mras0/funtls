#include <iostream>
#include <cstdint>
#include <vector>
#include <string>

#include <boost/asio.hpp>

#include "tls.h"
#include "tls_ciphers.h"

#include <hash/hash.h>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <aes/aes.h>
#include <util/base_conversion.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

// http://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl
// openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
// cat server_key.pem server_cert.pem >server.pem
// openssl s_server


namespace {

std::vector<uint8_t> vec_concat(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), a.begin(), a.end());
    combined.insert(combined.end(), b.begin(), b.end());
    return combined;
}

std::vector<uint8_t> HMAC_hash(const std::vector<uint8_t>& secret, const std::vector<uint8_t>& data) {
    // Assumes HMAC is SHA256 based
    assert(!secret.empty());
    assert(!data.empty());
    return hash::hmac_sha256{secret}.input(data).result();
}

std::vector<uint8_t> P_hash(const std::vector<uint8_t>& secret, const std::vector<uint8_t>& seed, size_t wanted_size) {
    assert(!secret.empty());
    assert(!seed.empty());
    assert(wanted_size != 0);
    // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    //                        HMAC_hash(secret, A(2) + seed) +
    //                        HMAC_hash(secret, A(3) + seed) + ...
    // A() is defined as:
    //    A(0) = seed
    //    A(i) = HMAC_hash(secret, A(i-1))

    std::vector<uint8_t> a = seed; // A(0) = seed

    // P_hash can be iterated as many times as necessary to produce the
    // required quantity of data.  For example, if P_SHA256 is being used to
    // create 80 bytes of data, it will have to be iterated three times
    // (through A(3)), creating 96 bytes of output data; the last 16 bytes
    // of the final iteration will then be discarded, leaving 80 bytes of
    // output data.

    std::vector<uint8_t> result;
    while (result.size() < wanted_size) {
        a = HMAC_hash(secret, a); // A(i) = HMAC_hash(secret, A(i-1))
        auto digest = HMAC_hash(secret, vec_concat(a, seed));
        result.insert(result.end(), digest.begin(), digest.end());
    }

    assert(result.size() >= wanted_size);
    return {result.begin(), result.begin() + wanted_size};
}

// Pseudo Random Function rfc5246 section 5
std::vector<uint8_t> PRF(const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& seed, size_t wanted_size) {
    // PRF(secret, label, seed) = P_<hash>(secret, label + seed)
    return P_hash(secret, vec_concat(std::vector<uint8_t>{label.begin(), label.end()}, seed), wanted_size);
}

} // unnamed namespace

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
        send_change_cipher_spec(); // calls send_finished();
        read_change_cipher_spec();
        read_finished();

        std::cout << "Session " << util::base16_encode(sesion_id.as_vector()) << " in progress\n";
    }

private:
    static constexpr size_t         master_secret_size = 48;

    const tls::protocol_version     current_protocol_version = tls::protocol_version_tls_1_2;
    const tls::cipher_suite         wanted_cipher            = tls::rsa_with_aes_256_cbc_sha256;

    boost::asio::ip::tcp::socket&   socket;
    const tls::random               our_random;
    tls::random                     their_random;
    std::vector<uint8_t>            their_certificate;
    tls::session_id                 sesion_id;
    std::vector<uint8_t>            master_secret;
    hash::sha256                    handshake_message_digest;

    // TODO: This only works when the payload isn't encrypted/compressed
    template<typename Payload>
    void send_record(Payload&& payload) {
        std::vector<uint8_t> buffer;
        tls::append_to_buffer(buffer,
            tls::record{
                current_protocol_version,
                std::forward<Payload>(payload)
            });
        handshake_message_digest.input(buffer);

        std::cout << "Sending record: " << util::base16_encode(buffer) << std::endl;
        boost::asio::write(socket, boost::asio::buffer(buffer));
    }

    tls::record read_record() {
        std::vector<uint8_t> buffer(5);
        boost::asio::read(socket, boost::asio::buffer(buffer));
        handshake_message_digest.input(buffer);

        size_t index = 0;
        tls::content_type     content_type;
        tls::protocol_version protocol_version;
        tls::uint16           length;
        tls::from_bytes(content_type, buffer, index);
        tls::from_bytes(protocol_version, buffer, index);
        tls::from_bytes(length, buffer, index);
        assert(index == buffer.size());

        if (protocol_version != current_protocol_version) {
            throw std::runtime_error("Invalid record protocol version " + util::base16_encode(&protocol_version, sizeof(protocol_version)) + " in " + __func__);
        }
        if (length < 1 || length > tls::record::max_length) {
            throw std::runtime_error("Invalid record length " + std::to_string(length) + " in " + __func__);
        }
        buffer.resize(length);
        boost::asio::read(socket, boost::asio::buffer(buffer));
        handshake_message_digest.input(buffer);
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
            throw std::runtime_error("Invalid cipher suite " + util::base16_encode(&server_hello.cipher_suite, 2));
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

        their_certificate = certificate_lists[0].certificate_list[0].as_vector();

        // TODO: Verify certificate(s)
    }

    void send_client_key_exchange() {
        // OK, now it's time to do ClientKeyExchange
        // Since we're doing RSA, we'll be sending the EncryptedPreMasterSecret

        // Prepare pre-master secret (version + 46 random bytes)
        std::vector<uint8_t> pre_master_secret(master_secret_size);
        pre_master_secret[0] = current_protocol_version.major;
        pre_master_secret[1] = current_protocol_version.minor;
        tls::get_random_bytes(&pre_master_secret[2], 46);

        // TODO: Encrypt pre_master_secret using the public key from the server's certificate
        std::cout << "Not encrypting pre-master secret in " << __PRETTY_FUNCTION__ << std::endl;

        // TODO: Make sure the certificate is correct etc.
        auto cert_buf = util::buffer_view{&their_certificate[0], their_certificate.size()};
        const auto cert = x509::v3_certificate::parse(asn1::read_der_encoded_value(cert_buf));
        const auto s_pk = rsa_public_key_from_certificate(cert);
        const auto n = s_pk.modolus.as<int_type>();
        const auto e = s_pk.public_exponent.as<int_type>();
        std::cout << "n:\n" << n << "\ne:\n" << e << std::endl;

        // Perform RSAES-PKCS1-V1_5-ENCRYPT (http://tools.ietf.org/html/rfc3447 7.2.1)

        // Build message to encrypt: EM = 0x00 || 0x02 || PS || 0x00 || M
        std::vector<uint8_t> EM(11);
        EM[0] = 0x00;
        EM[1] = 0x02;
        // PS = at least 8 pseudo random characters
        tls::get_random_bytes(&EM[2], 8);
        EM[10] = 0x00;
        // M = message to encrypt
        EM.insert(EM.end(), std::begin(pre_master_secret), std::end(pre_master_secret));

        // 3.a
        const auto m = x509::base256_decode<int_type>(EM); // m = OS2IP (EM)
        assert(m < n); // Is the message too long?

        // 3.b
        const int_type c = powm(m, e, n); // c = RSAEP ((n, e), m)
        std::cout << "c:\n" << c << std::endl;

        // 3.c Convert the ciphertext representative c to a ciphertext C of length k octets
        // C = I2OSP (c, k)
        const auto C = x509::base256_encode(c, s_pk.modolus.octet_count());
        std::cout << "C:\n" << util::base16_encode(C) << std::endl;

        tls::client_key_exchange client_key_exchange{tls::vector<tls::uint8,0,(1<<16)-1>{C}};
        send_record(tls::handshake{client_key_exchange});


        // We can now compute the master_secret as specified in rfc5246 8.1
        // master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]

        std::vector<uint8_t> rand_buf;
        tls::append_to_buffer(rand_buf, our_random);
        tls::append_to_buffer(rand_buf, their_random);
        master_secret = PRF(pre_master_secret, "master secret", rand_buf, master_secret_size);
        assert(master_secret.size() == master_secret_size);
        std::cout << "Master secret: " << util::base16_encode(master_secret) << std::endl;
    }

    void send_change_cipher_spec() {
        send_record(tls::change_cipher_spec{});
        // A Finished message is always sent immediately after a change
        // cipher spec message to verify that the key exchange and
        // authentication processes were successful
        send_finished();
    }

    void send_finished() {
        //
        // The data to include in the finished handshake is "verify_data":
        //
        // verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1]
        // finished_label: 
        //      For Finished messages sent by the client, the string "client finished".
        //      For Finished messages sent by the server, the string "server finished".
        // handshake_messages:
        //      All of the data from all messages in this handshake (not
        //      including any HelloRequest messages) up to, but not including,
        //      this message
        auto verify_data = PRF(master_secret, "client finished", handshake_message_digest.result(), tls::finished::verify_data_length);
        std::cout << "Verify data: " << util::base16_encode(verify_data) << std::endl;
        assert(verify_data.size() == tls::finished::verify_data_length);

        auto content = verify_data;
        std::cout << "****\nNot sending real data in " << __PRETTY_FUNCTION__ << "\n***\n";

        //
        // Compress (trivial for CompressionMethod.null) and secure the content
        // in a TLSCiphertext structure.
        //
        // 6.2.3.2.  CBC Block Cipher
        // struct {
        //     opaque IV[SecurityParameters.record_iv_length];
        //     block-ciphered struct {
        //         opaque content[TLSCompressed.length];
        //         opaque MAC[SecurityParameters.mac_length];
        //         uint8 padding[GenericBlockCipher.padding_length];
        //         uint8 padding_length;
        //     };
        // } GenericBlockCipher;
        std::vector<uint8_t> payload_buffer(aes::block_size_bytes);
        tls::get_random_bytes(&payload_buffer[0], aes::block_size_bytes); // Construct Initialization Vector
        tls::append_to_buffer(payload_buffer, content);

        // IV = Initialization Vector - SHOULD be chosen at random
        // For block ciphers, the IV length is of length SecurityParameters.record_iv_length, 
        // which is equal to the SecurityParameters.block_size.


        // The MAC is generated as:
        // MAC(MAC_write_key, seq_num +
        //                  TLSCompressed.type +
        //                  TLSCompressed.version +
        //                  TLSCompressed.length +
        //                  TLSCompressed.fragment);
        //
        // padding:
        //    Padding that is added to force the length of the plaintext to be
        //    an integral multiple of the block cipher's block length.
        // padding_length:
        //    The padding length MUST be such that the total size of the
        //    GenericBlockCipher structure is a multiple of the cipher's block
        //    length.  Legal values range from zero to 255, inclusive.  This
        //    length specifies the length of the padding field exclusive of the
        //    padding_length field itself.


        constexpr auto handshake_type = tls::handshake_type::finished;
        std::vector<uint8_t> fragment;
        tls::append_to_buffer(fragment, handshake_type);
        tls::append_to_buffer(fragment, current_protocol_version);
        tls::append_to_buffer(fragment, tls::uint24(payload_buffer.size()));
        tls::append_to_buffer(fragment, payload_buffer);

        constexpr auto content_type = tls::content_type::handshake;
        std::vector<uint8_t> record_buffer;
        tls::append_to_buffer(record_buffer, content_type);
        tls::append_to_buffer(record_buffer, current_protocol_version);
        assert(fragment.size() < ((1<<14)+2048) && "Payload of TLSCiphertext MUST NOT exceed 2^14 + 2048");
        tls::append_to_buffer(record_buffer, tls::uint16(fragment.size()));
        tls::append_to_buffer(record_buffer, fragment);

        boost::asio::write(socket, boost::asio::buffer(record_buffer));
    }

    void read_change_cipher_spec(){
        (void) read_record().payload.get<tls::change_cipher_spec>();
        std::cout << "Got ChangeCipherSpec from server\n";
    }

    void read_finished() {
        auto record = read_record();
        auto& finished = record.payload.get<tls::handshake>().body.get<tls::finished>();
        std::cout << "Got finished from server: " << util::base16_encode(finished.verify_data.data, tls::finished::verify_data_length) << std::endl;
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
