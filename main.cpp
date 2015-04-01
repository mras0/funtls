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
        , client_random(tls::make_random()) {
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
    // HMAC-SHA256
    static constexpr size_t         mac_length         = 256/8;
    static constexpr size_t         mac_key_length     = 256/8;
    // AES_256_CBC
    static constexpr size_t         enc_key_length     = 256/8;
    static constexpr size_t         fixed_iv_length    = 128/8;
    static constexpr size_t         block_length       = 128/8;

    static constexpr size_t         master_secret_size = 48;

    const tls::protocol_version     current_protocol_version = tls::protocol_version_tls_1_2;
    const tls::cipher_suite         wanted_cipher            = tls::rsa_with_aes_256_cbc_sha256;

    boost::asio::ip::tcp::socket&   socket;
    const tls::random               client_random;
    tls::random                     server_random;
    std::vector<uint8_t>            their_certificate;
    tls::session_id                 sesion_id;
    std::vector<uint8_t>            master_secret;
    hash::sha256                    handshake_message_digest;

    uint64_t                        client_seq = 0;
    uint64_t                        server_seq = 0;

    std::vector<uint8_t>            client_mac_key;
    std::vector<uint8_t>            server_mac_key;
    std::vector<uint8_t>            client_enc_key;
    std::vector<uint8_t>            server_enc_key;
    std::vector<uint8_t>            client_iv;
    std::vector<uint8_t>            server_iv;

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
        ++client_seq;
        boost::asio::write(socket, boost::asio::buffer(buffer));
    }

    tls::record read_record() {
        std::vector<uint8_t> buffer(5);
        boost::asio::read(socket, boost::asio::buffer(buffer));
        handshake_message_digest.input(buffer);
        ++server_seq;

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
                client_random,
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
        server_random = server_hello.random;
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
        tls::get_random_bytes(&pre_master_secret[2], pre_master_secret.size()-2);

        std::cout << "Pre-master secret: " << util::base16_encode(&pre_master_secret[2], pre_master_secret.size()-2) << std::endl;

        // TODO: Make sure the certificate is correct etc.
        auto cert_buf = util::buffer_view{&their_certificate[0], their_certificate.size()};
        const auto cert = x509::v3_certificate::parse(asn1::read_der_encoded_value(cert_buf));
        const auto s_pk = rsa_public_key_from_certificate(cert);
        const auto n = s_pk.modolus.as<int_type>();
        const auto e = s_pk.public_exponent.as<int_type>();

        // Perform RSAES-PKCS1-V1_5-ENCRYPT (http://tools.ietf.org/html/rfc3447 7.2.1)

        // Get k=message length
        size_t k = s_pk.modolus.octet_count(); // Length of modolus
        assert(k!=0);
        if (s_pk.modolus.octet(0) == 0) {
            // The leading byte of the modulos was 0, discount it in calculating the
            // bit length
            k--;
            assert(k && (s_pk.modolus.octet(1) & 0x80)); // The leading byte should only be 0 if the msb is set on the next byte
        }

        // Build message to encrypt: EM = 0x00 || 0x02 || PS || 0x00 || M
        std::vector<uint8_t> EM(k-pre_master_secret.size());
        EM[0] = 0x00;
        EM[1] = 0x02;
        // PS = at least 8 pseudo random characters (must be non-zero for type 0x02)
        tls::get_random_bytes(&EM[2], EM.size()-3);
        for (size_t i = 2; i < EM.size()-1; ++i) {
            while (!EM[i]) {
                tls::get_random_bytes(&EM[i], 1);
            }
        }
        EM[EM.size()-1] = 0x00;
        // M = message to encrypt
        EM.insert(EM.end(), std::begin(pre_master_secret), std::end(pre_master_secret));
        assert(EM.size()==k);

        // 3.a
        const auto m = x509::base256_decode<int_type>(EM); // m = OS2IP (EM)
        assert(m < n); // Is the message too long?

        std::cout << "m (" << EM.size() << ") = " << util::base16_encode(EM) << std::dec << "\n";

        // 3.b
        const int_type c = powm(m, e, n); // c = RSAEP ((n, e), m)
        std::cout << "c:\n" << c << std::endl;

        // 3.c Convert the ciphertext representative c to a ciphertext C of length k octets
        // C = I2OSP (c, k)
        const auto C = x509::base256_encode(c, k);
        std::cout << "C:\n" << util::base16_encode(C) << std::endl;

        tls::client_key_exchange client_key_exchange{tls::vector<tls::uint8,0,(1<<16)-1>{C}};
        send_record(tls::handshake{client_key_exchange});


        // We can now compute the master_secret as specified in rfc5246 8.1
        // master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]

        std::vector<uint8_t> rand_buf;
        tls::append_to_buffer(rand_buf, client_random);
        tls::append_to_buffer(rand_buf, server_random);
        master_secret = PRF(pre_master_secret, "master secret", rand_buf, master_secret_size);
        assert(master_secret.size() == master_secret_size);
        std::cout << "Master secret: " << util::base16_encode(master_secret) << std::endl;

        // Now do Key Calculation http://tools.ietf.org/html/rfc5246#section-6.3
        // key_block = PRF(SecurityParameters.master_secret, "key expansion",
        // SecurityParameters.server_random + SecurityParameters.client_random)
        const size_t key_block_length  = 2 * mac_key_length + 2 * enc_key_length + 2 * fixed_iv_length;
        auto key_block = PRF(master_secret, "key expansion", vec_concat(server_random.as_vector(), client_random.as_vector()), key_block_length);

        size_t i = 0;
        client_mac_key = std::vector<uint8_t>{&key_block[i], &key_block[i+mac_key_length]}; i += mac_key_length;
        server_mac_key = std::vector<uint8_t>{&key_block[i], &key_block[i+mac_key_length]}; i += mac_key_length;
        client_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+enc_key_length]}; i += enc_key_length;
        server_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+enc_key_length]}; i += enc_key_length;
        client_iv      = std::vector<uint8_t>{&key_block[i], &key_block[i+fixed_iv_length]}; i += fixed_iv_length;
        server_iv      = std::vector<uint8_t>{&key_block[i], &key_block[i+fixed_iv_length]}; i += fixed_iv_length;
        assert(i == key_block.size());
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
        // The data to include in the "finished" handshake is "verify_data":
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

        std::vector<uint8_t> content;
        tls::append_to_buffer(content, tls::handshake_type::finished);
        tls::append_to_buffer(content, tls::uint24(verify_data.size()));
        tls::append_to_buffer(content, verify_data);
        std::cout << "****\nNot sending real data in " << __PRETTY_FUNCTION__ << "\n***\n";

        constexpr auto content_type = tls::content_type::handshake;

        //
        // We now have our plaintext content to send (content).
        // First apply compression (trivial for CompressionMethod.null)
        // The next step is generating a MAC of the content
        //

        // The MAC is generated as:
        // MAC(MAC_write_key, seq_num +
        //                  TLSCompressed.type +
        //                  TLSCompressed.version +
        //                  TLSCompressed.length +
        //                  TLSCompressed.fragment);
        auto hash_algo = hash::hmac_sha256(client_mac_key);
        assert(client_seq < 256);
        hash_algo.input(std::vector<uint8_t>{0,0,0,0,0,0,0,(uint8_t)client_seq});
        hash_algo.input(static_cast<const void*>(&content_type), 1);
        hash_algo.input(&current_protocol_version.major, 1);
        hash_algo.input(&current_protocol_version.minor, 1);
        hash_algo.input(std::vector<uint8_t>{uint8_t(content.size()>>8),uint8_t(content.size())});
        hash_algo.input(content);
        const auto mac = hash_algo.result();
        std::cout << "MAC: " << util::base16_encode(mac) << std::endl;

        // 
        // Assemble content, mac and padding
        //
        // opaque content[TLSCompressed.length];
        // opaque MAC[SecurityParameters.mac_length];
        // uint8 padding[GenericBlockCipher.padding_length];
        // uint8 padding_length;
        //
        std::vector<uint8_t> content_and_mac;
        tls::append_to_buffer(content_and_mac, content);
        tls::append_to_buffer(content_and_mac, mac);
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
        //
        uint8_t padding_length = block_length - (content_and_mac.size()+1) % block_length;
        for (unsigned i = 0; i < padding_length + 1U; ++i) {
            content_and_mac.push_back(padding_length);
        }
        assert(content_and_mac.size() % block_length == 0);

        //
        // A GenericBlockCipher consist of the initialization vector and block-ciphered
        // content, mac and padding.
        //
        std::vector<uint8_t> fragment;
        tls::append_to_buffer(fragment, client_iv);
        tls::append_to_buffer(fragment, aes::aes_encrypt_cbc(client_enc_key, client_iv, content_and_mac));


        //
        // Now create and send the actual TLSCiphertext structure
        //
        std::vector<uint8_t> ciphertext_buffer;
        tls::append_to_buffer(ciphertext_buffer, content_type);
        tls::append_to_buffer(ciphertext_buffer, current_protocol_version);
        assert(fragment.size() < ((1<<14)+2048) && "Payload of TLSCiphertext MUST NOT exceed 2^14 + 2048");
        tls::append_to_buffer(ciphertext_buffer, tls::uint16(fragment.size()));
        tls::append_to_buffer(ciphertext_buffer, fragment);
        boost::asio::write(socket, boost::asio::buffer(ciphertext_buffer));
        ++client_seq;
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
