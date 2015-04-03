#include <iostream>
#include <cstdint>
#include <vector>
#include <string>

#include <boost/asio.hpp>

#include <hash/hash.h>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <aes/aes.h>
#include <util/base_conversion.h>
#include <util/test.h>
#include <tls/tls.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

// http://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl
// openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
// cat server_key.pem server_cert.pem >server.pem
// openssl s_server


namespace {

} // unnamed namespace

namespace funtls { namespace tls {

enum class connection_end { server, client };


} } // namespace funtls::tls

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

        std::cout << "Requesting " << wanted_cipher << std::endl;
        send_client_hello();
        read_server_hello();
        read_until_server_hello_done();
        send_client_key_exchange();
        send_change_cipher_spec(); // calls send_finished();
        read_change_cipher_spec();
        read_finished();

        std::cout << "Session " << util::base16_encode(sesion_id.as_vector()) << " in progress\n";
    }

    void send_app_data(const std::vector<uint8_t>& d) {
        send_record(tls::content_type::application_data, d);
    }

    std::vector<uint8_t> next_app_data() {
        const auto record = read_record();
        FUNTLS_CHECK_BINARY(record.type, ==, tls::content_type::application_data, "Unexpected content type");
        return record.fragment;
    }

private:
    static constexpr size_t         master_secret_size = 48;

    const tls::protocol_version     current_protocol_version = tls::protocol_version_tls_1_2;
    //const tls::cipher_suite         wanted_cipher            = tls::cipher_suite::rsa_with_aes_128_cbc_sha;
    const tls::cipher_suite         wanted_cipher            = tls::cipher_suite::rsa_with_aes_128_cbc_sha256;
    //const tls::cipher_suite         wanted_cipher            = tls::cipher_suite::rsa_with_aes_256_cbc_sha;
    //const tls::cipher_suite         wanted_cipher            = tls::cipher_suite::rsa_with_aes_256_cbc_sha256;
    tls::cipher_suite               current_cipher           = tls::cipher_suite::null_with_null_null;

    boost::asio::ip::tcp::socket&   socket;
    const tls::random               client_random;
    tls::random                     server_random;
    std::unique_ptr<
        x509::rsa_public_key>       server_public_key;
    tls::session_id                 sesion_id;
    std::vector<uint8_t>            master_secret;
    hash::sha256                    handshake_message_digest;
    uint64_t                        sequence_number = 0; // TODO: A seperate sequence number is used for each connection end

    std::vector<uint8_t>            client_mac_key;
    std::vector<uint8_t>            server_mac_key;
    std::vector<uint8_t>            client_enc_key;
    std::vector<uint8_t>            server_enc_key;

    // TODO: This only works when the payload isn't encrypted/compressed
    template<typename Payload>
    void send_record(const Payload& payload) {
        std::vector<uint8_t> payload_buffer;
        append_to_buffer(payload_buffer, payload);

        send_record(payload.content_type, payload_buffer);
        if (payload.content_type == tls::content_type::handshake) {
            // HACK
            handshake_message_digest.input(payload_buffer);
        }
    }

    tls::handshake read_handshake() {
        auto record = read_record();
        FUNTLS_CHECK_BINARY(record.type, ==, tls::content_type::handshake, "Invalid content type");

        size_t index = 0;
        auto handshake = tls::handshake_from_bytes(record.fragment, index);
        assert(index == record.fragment.size());
        handshake_message_digest.input(record.fragment);
        return handshake;
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
        auto handshake = read_handshake();
        auto& server_hello = handshake.body.get<tls::server_hello>();
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
            auto handshake = read_handshake();
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
            throw std::runtime_error("Unsupported number of certificate lists: " + std::to_string(certificate_lists.size()));
        }

        // TODO: Make sure the certificate is correct etc.
        // TODO: Verify certificate(s)

        for (const auto& c : certificate_lists[0].certificate_list) {
            const auto v = c.as_vector();
            auto cert_buf = util::buffer_view{&v[0], v.size()};
            const auto cert = x509::v3_certificate::parse(asn1::read_der_encoded_value(cert_buf)).certificate();
            std::cout << "Ignoring certificate:\n";
            std::cout << " Issuer: " << cert.issuer << std::endl;
            std::cout << " Subject: " << cert.subject << std::endl;
        }

        const auto their_certificate = certificate_lists[0].certificate_list[0].as_vector();
        auto cert_buf = util::buffer_view{&their_certificate[0], their_certificate.size()};
        const auto cert = x509::v3_certificate::parse(asn1::read_der_encoded_value(cert_buf));
        server_public_key.reset(new x509::rsa_public_key(rsa_public_key_from_certificate(cert)));
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

        assert(server_public_key);
        const auto& s_pk = *server_public_key;
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
        master_secret = tls::PRF(pre_master_secret, "master secret", rand_buf, master_secret_size);
        assert(master_secret.size() == master_secret_size);
        std::cout << "Master secret: " << util::base16_encode(master_secret) << std::endl;

        // Now do Key Calculation http://tools.ietf.org/html/rfc5246#section-6.3
        // key_block = PRF(SecurityParameters.master_secret, "key expansion",
        // SecurityParameters.server_random + SecurityParameters.client_random)
        const auto cipher_param = tls::parameters_from_suite(wanted_cipher);
        const size_t key_block_length  = 2 * cipher_param.mac_key_length + 2 * cipher_param.key_length;
        auto key_block = tls::PRF(master_secret, "key expansion", tls::vec_concat(server_random.as_vector(), client_random.as_vector()), key_block_length);

        size_t i = 0;
        client_mac_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.mac_key_length]}; i += cipher_param.mac_key_length;
        server_mac_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.mac_key_length]}; i += cipher_param.mac_key_length;
        client_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.key_length]}; i += cipher_param.key_length;
        server_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.key_length]}; i += cipher_param.key_length;
        // Only used for TLS v1.1 and earlier
        //client_iv      = std::vector<uint8_t>{&key_block[i], &key_block[i+fixed_iv_length]}; i += fixed_iv_length;
        //server_iv      = std::vector<uint8_t>{&key_block[i], &key_block[i+fixed_iv_length]}; i += fixed_iv_length;
        assert(i == key_block.size());
    }

    void send_change_cipher_spec() {
        send_record(tls::change_cipher_spec{});
        // A Finished message is always sent immediately after a change
        // cipher spec message to verify that the key exchange and
        // authentication processes were successful
        current_cipher = wanted_cipher; // HACKISH
        send_finished();
        current_cipher = tls::cipher_suite::null_with_null_null; // HACKISH
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
        std::cout << "Hash(handshake_messages) = " << util::base16_encode(handshake_message_digest.result()) << std::endl;
        auto verify_data = tls::PRF(master_secret, "client finished", handshake_message_digest.result(), tls::finished::verify_data_length);
        std::cout << "Verify data: " << util::base16_encode(verify_data) << std::endl;
        assert(verify_data.size() == tls::finished::verify_data_length);

        std::vector<uint8_t> content;
        tls::append_to_buffer(content, tls::handshake_type::finished);
        tls::append_to_buffer(content, tls::uint24(verify_data.size()));
        tls::append_to_buffer(content, verify_data);

        handshake_message_digest.input(content); // Now safe to update since we've used 

        send_record(tls::content_type::handshake, content);
    }

    void send_record(tls::content_type type, const std::vector<uint8_t>& plaintext) {
        FUNTLS_CHECK_BINARY(plaintext.size(), >=, 1, "Illegal plain text size");
        FUNTLS_CHECK_BINARY(plaintext.size(), <=, tls::record::max_plaintext_length, "Illegal plain text size");

        //
        // We have our plaintext content to send (content).
        // First apply compression (trivial for CompressionMethod.null)
        // TODO
        //

        //
        // Do encryption
        //
        auto fragment = encrypt(type, plaintext);
        FUNTLS_CHECK_BINARY(fragment.size(), <=, tls::record::max_ciphertext_length, "Illegal fragment size");

        std::vector<uint8_t> header;
        tls::append_to_buffer(header, type);
        tls::append_to_buffer(header, current_protocol_version);
        tls::append_to_buffer(header, tls::uint16(fragment.size()));
        assert(header.size() == 5);

        boost::asio::write(socket, boost::asio::buffer(header));
        boost::asio::write(socket, boost::asio::buffer(fragment));
    }

    std::vector<uint8_t> encrypt(tls::content_type content_type, const std::vector<uint8_t>& content) {
        if (current_cipher == tls::cipher_suite::null_with_null_null) {
            return content;
        }
        const auto cipher_param = tls::parameters_from_suite(current_cipher);

        // The MAC is generated as:
        // MAC(MAC_write_key, seq_num +
        //                  TLSCompressed.type +
        //                  TLSCompressed.version +
        //                  TLSCompressed.length +
        //                  TLSCompressed.fragment);
        auto hash_algo = tls::get_hmac(cipher_param.mac_algorithm, client_mac_key);
        assert(sequence_number < 256);
        hash_algo.input(std::vector<uint8_t>{0,0,0,0,0,0,0,static_cast<uint8_t>(sequence_number)});
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
        const auto block_length = cipher_param.block_length;
        uint8_t padding_length = block_length - (content_and_mac.size()+1) % block_length;
        for (unsigned i = 0; i < padding_length + 1U; ++i) {
            content_and_mac.push_back(padding_length);
        }
        assert(content_and_mac.size() % block_length == 0);

        //
        // A GenericBlockCipher consist of the initialization vector and block-ciphered
        // content, mac and padding.
        //
        assert(cipher_param.bulk_cipher_algorithm == tls::bulk_cipher_algorithm::aes);
        std::vector<uint8_t> fragment;
        std::vector<uint8_t> message_iv(cipher_param.iv_length);
        tls::get_random_bytes(&message_iv[0], message_iv.size());
        tls::append_to_buffer(fragment, message_iv);
        tls::append_to_buffer(fragment, aes::aes_encrypt_cbc(client_enc_key, message_iv, content_and_mac));

        assert(fragment.size() < ((1<<14)+2048) && "Payload of TLSCiphertext MUST NOT exceed 2^14 + 2048");
        return fragment;
    }

    void read_change_cipher_spec(){
        auto record = read_record();
        FUNTLS_CHECK_BINARY(record.type,            ==, tls::content_type::change_cipher_spec, "Invalid content type");
        FUNTLS_CHECK_BINARY(record.fragment.size(), ==, 1, "Invalid ChangeCipherSpec fragment size");
        FUNTLS_CHECK_BINARY(record.fragment[0],     !=, 0, "Invalid ChangeCipherSpec fragment data");
        std::cout << "Got ChangeCipherSpec from server\n";
        current_cipher = wanted_cipher;
    }

    void read_finished() {
        const auto record = read_record();
        assert(record.type == tls::content_type::handshake);
        const auto& content = record.fragment;
        // Parse content
        assert(content.size() >= 5);
        assert(content[0] == (int)tls::handshake_type::finished);
        assert(content[1] == 0);
        assert(content[2] == 0);
        assert(content[3] == tls::finished::verify_data_length);
        assert(content.size() == 4U + content[3]);
        const std::vector<uint8_t> verify_data{&content[4], &content[content.size()]};

        std::cout << "verify_data\n" << util::base16_encode(verify_data) << std::endl;
        std::cout << "Hash(handshake_messages) = " << util::base16_encode(handshake_message_digest.result()) << std::endl;
        const auto calced_verify_data = tls::PRF(master_secret, "server finished", handshake_message_digest.result(), tls::finished::verify_data_length);
        std::cout << "calculated verify_data\n" << util::base16_encode(calced_verify_data) << std::endl;
        assert(verify_data == calced_verify_data);
    }

    tls::record read_record() {
        std::vector<uint8_t> buffer(5);
        boost::asio::read(socket, boost::asio::buffer(buffer));

        size_t index = 0;
        tls::content_type     content_type;
        tls::protocol_version protocol_version;
        tls::uint16           length;
        tls::from_bytes(content_type, buffer, index);
        tls::from_bytes(protocol_version, buffer, index);
        tls::from_bytes(length, buffer, index);
        assert(index == buffer.size());

        FUNTLS_CHECK_BINARY(protocol_version, ==, current_protocol_version, "Wrong TLS version");
        FUNTLS_CHECK_BINARY(length, >=, 1, "Illegal fragment size");
        FUNTLS_CHECK_BINARY(length, <=, tls::record::max_ciphertext_length, "Illegal fragment size");

        buffer.resize(length);
        boost::asio::read(socket, boost::asio::buffer(buffer));

        //
        // Decrypt
        //
        if (current_cipher != tls::cipher_suite::null_with_null_null) {
            decrypt(content_type, buffer);
        }

        //
        // Decompression
        //
        // TODO: decompress buffer -> buffer
        FUNTLS_CHECK_BINARY(buffer.size(), <=, tls::record::max_compressed_length, "Illegal decoded fragment size");

        //
        // We now have a TLSPlaintext buffer for consumption
        //
        FUNTLS_CHECK_BINARY(buffer.size(), <=, tls::record::max_plaintext_length, "Illegal decoded fragment size");

        return tls::record{content_type, protocol_version, std::move(buffer)};
    }

    void decrypt(tls::content_type record_type, std::vector<uint8_t>& buffer) {
        assert(buffer.size() <= tls::record::max_ciphertext_length);

        // TODO: improve really lazy parsing/validation
        const auto cipher_param = tls::parameters_from_suite(current_cipher);

        FUNTLS_CHECK_BINARY(buffer.size(), >=, cipher_param.iv_length, "Message too small"); // needs work..

        const std::vector<uint8_t> message_iv{&buffer[0], &buffer[cipher_param.iv_length]};
        const std::vector<uint8_t> encrypted{&buffer[cipher_param.iv_length], &buffer[buffer.size()]};

        //std::cout << "IV\n" << util::base16_encode(message_iv)  << std::endl;
        //std::cout << "Encrypted\n" << util::base16_encode(encrypted)  << std::endl;

        //std::cout << "server_key\n" << util::base16_encode(server_enc_key)  << std::endl;

        const auto decrypted = aes::aes_decrypt_cbc(server_enc_key, message_iv, encrypted);
        //std::cout << "Decrypted\n" << util::base16_encode(decrypted) << std::endl;

        // check padding
        const auto padding_length = decrypted[decrypted.size()-1];
        assert(decrypted.size() % cipher_param.block_length == 0);
        assert(padding_length + 1U < decrypted.size()); // Padding+Padding length byte musn't be sole contents
        for (unsigned i = 0; i < padding_length; ++i) assert(decrypted[decrypted.size()-1-padding_length] == padding_length);

        // Extract MAC + Content
        const size_t mac_index = decrypted.size()-1-padding_length-cipher_param.mac_length;
        const std::vector<uint8_t> mac{&decrypted[mac_index],&decrypted[mac_index+cipher_param.mac_length]};
        //std::cout << "MAC\n" << util::base16_encode(mac) << std::endl;

        const std::vector<uint8_t> content{&decrypted[0],&decrypted[mac_index]};
        //std::cout << "Content\n" << util::base16_encode(content) << std::endl;

        // Check MAC -- TODO: Unify with do_send
        auto hash_algo = tls::get_hmac(cipher_param.mac_algorithm, server_mac_key);
        assert(sequence_number < 256);
        hash_algo.input(std::vector<uint8_t>{0,0,0,0,0,0,0,static_cast<uint8_t>(sequence_number)});
        hash_algo.input(static_cast<const void*>(&record_type), 1);
        hash_algo.input(&current_protocol_version.major, 1);
        hash_algo.input(&current_protocol_version.minor, 1);
        hash_algo.input(std::vector<uint8_t>{uint8_t(content.size()>>8),uint8_t(content.size())});
        hash_algo.input(content);
        const auto calced_mac = hash_algo.result();
        std::cout << "Calculated MAC\n" << util::base16_encode(calced_mac) << std::endl;
        assert(calced_mac == mac);

        sequence_number++;

        buffer = std::move(content);
    }
};

int main(int argc, char* argv[])
{
    const char* const host = argc > 1 ? argv[1] : "localhost";
    const char* const port = argc > 2 ? argv[2] : "443";

    try {
        boost::asio::io_service         io_service;
        boost::asio::ip::tcp::socket    socket(io_service);
        boost::asio::ip::tcp::resolver  resolver(io_service);

        std::cout << "Connecting to " << host << ":" << port << " ..." << std::flush;
        boost::asio::connect(socket, resolver.resolve({host, port}));
        std::cout << " OK" << std::endl;
        tls_socket ts{socket};
        ts.perform_handshake();

        std::cout << "Completed handshake!\n";

        const auto data = std::string("GET / HTTP/1.1\r\nHost: ")+host+"\r\n\r\n";
        ts.send_app_data(std::vector<uint8_t>(data.begin(), data.end()));

        for (;;) {
            const auto res = ts.next_app_data();
            std::cout << std::string(res.begin(), res.end()) << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Caught unknown exception" << std::endl;
        return 1;
    }
    return 0;
}
