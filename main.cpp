#include <iostream>
#include <cstdint>
#include <vector>
#include <string>

#include <boost/asio.hpp>

#include <hash/hash.h>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <util/base_conversion.h>
#include <util/test.h>
#include <util/buffer.h>
#include <tls/tls.h>

//#define WRITE_CERTS
#ifdef WRITE_CERTS
#include <fstream>
#include <x509/x509_io.h>
#endif

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

namespace {

std::pair<std::vector<uint8_t>, tls::handshake> client_key_exchange_rsa(tls::protocol_version protocol_version, const x509::rsa_public_key& server_public_key) {
    // OK, now it's time to do ClientKeyExchange
    // Since we're doing RSA, we'll be sending the EncryptedPreMasterSecret

    // Prepare pre-master secret (version + 46 random bytes)
    std::vector<uint8_t> pre_master_secret(tls::master_secret_size);
    pre_master_secret[0] = protocol_version.major;
    pre_master_secret[1] = protocol_version.minor;
    tls::get_random_bytes(&pre_master_secret[2], pre_master_secret.size()-2);

    const auto C = x509::pkcs1_encode(server_public_key, pre_master_secret, &tls::get_random_bytes);
    tls::client_key_exchange_rsa client_key_exchange{tls::vector<tls::uint8,0,(1<<16)-1>{C}};
    return std::make_pair(std::move(pre_master_secret), make_handshake(client_key_exchange));
}

std::pair<std::vector<uint8_t>, tls::handshake> client_key_exchange_dhe_rsa(const tls::server_dh_params& server_dh_params) {
    const size_t key_size = server_dh_params.dh_p.size();
    //std::cout << "Should generate int of size " << key_size*8 << " bits " << std::endl;
    std::vector<uint8_t> rand_int(key_size);
    do {
        tls::get_random_bytes(&rand_int[0], rand_int.size());
    } while (std::find_if(rand_int.begin(), rand_int.end(), [](uint8_t i) { return i != 0; }) == rand_int.end());

    const int_type private_key = x509::base256_decode<int_type>(rand_int);

    //std::cout << "DHE client private key: " << std::hex << private_key << std::dec << std::endl;

    const int_type p  = x509::base256_decode<int_type>(server_dh_params.dh_p.as_vector());
    const int_type g  = x509::base256_decode<int_type>(server_dh_params.dh_g.as_vector());
    const int_type Ys = x509::base256_decode<int_type>(server_dh_params.dh_Ys.as_vector());
    const int_type Yc = powm(g, private_key, p);
    const auto dh_Yc  = x509::base256_encode(Yc, key_size);

    //std::cout << "dh_Yc = " << util::base16_encode(dh_Yc) << std::endl;

    tls::client_key_exchange_dhe_rsa client_key_exchange{tls::vector<tls::uint8,1,(1<<16)-1>{dh_Yc}};
    auto handshake = make_handshake(client_key_exchange);

    const int_type Z = powm(Ys, private_key, p);
    auto dh_Z  = x509::base256_encode(Z, key_size);
    //std::cout << "Negotaited key = " << util::base16_encode(dh_Z) << std::endl;
    return std::make_pair(std::move(dh_Z), std::move(handshake));
}

void verify_dhe_signature(const tls::server_key_exchange_dhe& dhe_kex, const x509::rsa_public_key& public_key, const std::vector<uint8_t>& digest_buf)
{
    //std::cout << "Verifying server DHE signature\n";
    FUNTLS_CHECK_BINARY(dhe_kex.signature_algorithm, ==, tls::signature_algorithm::rsa, "");
    const auto digest = x509::pkcs1_decode(public_key, dhe_kex.signature.as_vector());
    if (digest.digest_algorithm == x509::id_sha1) {
        FUNTLS_CHECK_BINARY(tls::hash_algorithm::sha1, ==, dhe_kex.hash_algorithm, "");
    } else {
        // What hash algorithm should be used? What if there's a mismatch?
        std::ostringstream oss;
        oss << "Untested digest algorithm " << digest.digest_algorithm << ". Digest=" << util::base16_encode(digest.digest);
        FUNTLS_CHECK_FAILURE(oss.str());
    }

    const auto calced_digest = tls::get_hash(dhe_kex.hash_algorithm).input(digest_buf).result();
    //std::cout << "Calculated digest: " << util::base16_encode(calced_digest) << std::endl;

    FUNTLS_CHECK_BINARY(calced_digest.size(), ==, digest.digest.size(), "Wrong digest size");
    if (!std::equal(calced_digest.begin(), calced_digest.end(), digest.digest.begin())) {
        throw std::runtime_error("Digest mismatch in " + std::string(__PRETTY_FUNCTION__) + " Calculated: " +
                util::base16_encode(calced_digest) + " Expected: " +
                util::base16_encode(digest.digest));
    }
}

} // unnamed namespace

// http://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl
// openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
// cat server_key.pem server_cert.pem >server.pem
// openssl s_server

class tls_socket {
public:
    explicit tls_socket(boost::asio::ip::tcp::socket& socket)
        : socket(socket)
        , client_random(tls::make_random()) {
    }

    void perform_handshake(tls::cipher_suite wanted_cipher) {
        this->wanted_cipher = wanted_cipher;
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
    const tls::protocol_version     current_protocol_version = tls::protocol_version_tls_1_2;
    tls::cipher_suite               wanted_cipher;

    boost::asio::ip::tcp::socket&   socket;
    const tls::random               client_random;
    tls::random                     server_random;
    std::unique_ptr<
        x509::rsa_public_key>       server_public_key;
    std::unique_ptr<
        tls::server_dh_params>      server_dh_params;
    tls::session_id                 sesion_id;
    std::vector<uint8_t>            master_secret;
    hash::sha256                    handshake_message_digest;
    uint64_t                        encrypt_sequence_number = 0;
    uint64_t                        decrypt_sequence_number = 0;
    std::unique_ptr<tls::cipher>    encrypt_cipher = tls::make_cipher(tls::null_cipher_parameters_e);
    std::unique_ptr<tls::cipher>    decrypt_cipher = tls::make_cipher(tls::null_cipher_parameters_d);
    std::unique_ptr<tls::cipher>    pending_encrypt_cipher;
    std::unique_ptr<tls::cipher>    pending_decrypt_cipher;

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

        util::buffer_view frag_buf{&record.fragment[0], record.fragment.size()};
        tls::handshake handshake;
        tls::from_bytes(handshake, frag_buf);
        assert(frag_buf.remaining() == 0);
        handshake_message_digest.input(record.fragment);
        return handshake;
    }

    void send_client_hello() {
        send_record(tls::make_handshake(
            tls::client_hello{
                current_protocol_version,
                client_random,
                sesion_id,
                { wanted_cipher },
                { tls::compression_method::null },
            }
        ));
    }

    void read_server_hello() {
        auto handshake = read_handshake();
        auto server_hello = tls::get_as<tls::server_hello>(handshake);
        if (server_hello.cipher_suite != wanted_cipher) {
            throw std::runtime_error("Invalid cipher suite " + util::base16_encode(&server_hello.cipher_suite, 2));
        }
        if (server_hello.compression_method != tls::compression_method::null) {
            throw std::runtime_error("Invalid compression method " + std::to_string((int)server_hello.compression_method));
        }
        server_random = server_hello.random;
        sesion_id = server_hello.session_id;
    }

    // TODO: Improve this function
    void read_until_server_hello_done() {
        std::vector<tls::certificate> certificate_lists;

        static const tls::handshake_type handshake_order[] = {
            tls::handshake_type::certificate,
            tls::handshake_type::server_key_exchange,
            //tls::handshake_type::certificate_request
            tls::handshake_type::server_hello_done
        };

        const auto cipher_param = tls::parameters_from_suite(wanted_cipher);
        std::unique_ptr<tls::server_key_exchange_dhe> dhe_kex;

        static const size_t num_handshake_order = sizeof(handshake_order)/sizeof(*handshake_order);
        for (size_t order = 0; ; ) {
            auto handshake = read_handshake();
            while (handshake.type != handshake_order[order]) {
                ++order;
                FUNTLS_CHECK_BINARY(order, <, num_handshake_order, "Handshake of type " + std::to_string((int)handshake.type) + " received out of order");
            }

            if (handshake.type == tls::handshake_type::certificate) {
                certificate_lists.push_back(tls::get_as<tls::certificate>(handshake));
            } else if (handshake.type == tls::handshake_type::server_key_exchange) {
                // HACK
                FUNTLS_CHECK_BINARY(tls::key_exchange_algorithm::dhe_rsa, ==, cipher_param.key_exchange_algorithm, "");
                auto kex = tls::get_as<tls::server_key_exchange_dhe>(handshake);
                std::cout << "Got server key exchange! hash=" << kex.hash_algorithm << " signature=" << kex.signature_algorithm << std::endl;
                std::cout << "Signature: " << util::base16_encode(kex.signature.as_vector()) << std::endl;
                std::cout << "dh_p:      " << util::base16_encode(kex.params.dh_p.as_vector()) << std::endl;
                std::cout << "dh_g:      " << util::base16_encode(kex.params.dh_g.as_vector()) << std::endl;
                std::cout << "dh_Ys:     " << util::base16_encode(kex.params.dh_Ys.as_vector()) << std::endl;

                if (dhe_kex) {
                    FUNTLS_CHECK_FAILURE("More than one server_key_change_dhe messages");
                }
                dhe_kex.reset(new tls::server_key_exchange_dhe(kex));

            } else if (handshake.type == tls::handshake_type::server_hello_done) {
                FUNTLS_CHECK_BINARY(handshake.body.size(), ==, 0, "Invalid ServerHelloDone message");
                break;
            } else {
                FUNTLS_CHECK_FAILURE("Internal error: Unknown handshake type " + std::to_string((int)handshake.type));
            }
        }

        if (certificate_lists.size() != 1) {
            throw std::runtime_error("Unsupported number of certificate lists: " + std::to_string(certificate_lists.size()));
        }

        // TODO: Make sure the certificate is correct etc.
        // TODO: Verify certificate(s)

#ifdef WRITE_CERTS
        std::ofstream of("/tmp/certs.pem", std::fstream::binary);
        if (!of || !of.is_open()) throw std::runtime_error("Error opening certificate output file");
#endif
        for (const auto& c : certificate_lists[0].certificate_list) {
            const auto v = c.as_vector();
            auto cert_buf = util::buffer_view{&v[0], v.size()};
            const auto cert = x509::v3_certificate::parse(asn1::read_der_encoded_value(cert_buf)).certificate();
            std::cout << "Ignoring certificate:\n";
            std::cout << " Issuer: " << cert.issuer << std::endl;
            std::cout << " Subject: " << cert.subject << std::endl;

#ifdef WRITE_CERTS
            x509::write_pem_certificate(of, v);
            if (!of) throw std::runtime_error("Error writing to certificate output file");
#endif
        }

        const auto their_certificate = certificate_lists[0].certificate_list[0].as_vector();
        auto cert_buf = util::buffer_view{&their_certificate[0], their_certificate.size()};
        const auto cert = x509::v3_certificate::parse(asn1::read_der_encoded_value(cert_buf));
        server_public_key.reset(new x509::rsa_public_key(rsa_public_key_from_certificate(cert)));

        // HAX
        if (dhe_kex) {
            assert(server_public_key);
            std::vector<uint8_t> digest_buf;
            append_to_buffer(digest_buf, client_random);
            append_to_buffer(digest_buf, server_random);
            append_to_buffer(digest_buf, dhe_kex->params);
            verify_dhe_signature(*dhe_kex, *server_public_key, digest_buf);
            server_dh_params.reset(new tls::server_dh_params(dhe_kex->params));
        }
    }

    void send_client_key_exchange() {
        const auto cipher_param = tls::parameters_from_suite(wanted_cipher);
        std::vector<uint8_t> pre_master_secret;
        tls::handshake       client_key_exchange;
        if (cipher_param.key_exchange_algorithm == tls::key_exchange_algorithm::rsa) {
            assert(server_public_key);
            std::tie(pre_master_secret, client_key_exchange) = client_key_exchange_rsa(current_protocol_version, *server_public_key);
        } else if (cipher_param.key_exchange_algorithm == tls::key_exchange_algorithm::dhe_rsa) {
            assert(server_dh_params);
            std::tie(pre_master_secret, client_key_exchange) = client_key_exchange_dhe_rsa(*server_dh_params);
        } else {
            FUNTLS_CHECK_FAILURE("Internal error: Unsupported KeyExchangeAlgorithm " + std::to_string((int)(cipher_param.key_exchange_algorithm)));
        }
        send_record(client_key_exchange);
        // We can now compute the master_secret as specified in rfc5246 8.1
        // master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]

        std::vector<uint8_t> rand_buf;
        tls::append_to_buffer(rand_buf, client_random);
        tls::append_to_buffer(rand_buf, server_random);
        master_secret = tls::PRF(pre_master_secret, "master secret", rand_buf, tls::master_secret_size);
        assert(master_secret.size() == tls::master_secret_size);
        std::cout << "Master secret: " << util::base16_encode(master_secret) << std::endl;

        // Now do Key Calculation http://tools.ietf.org/html/rfc5246#section-6.3
        // key_block = PRF(SecurityParameters.master_secret, "key expansion",
        // SecurityParameters.server_random + SecurityParameters.client_random)
        const size_t key_block_length  = 2 * cipher_param.mac_key_length + 2 * cipher_param.key_length + 2 * cipher_param.fixed_iv_length;
        auto key_block = tls::PRF(master_secret, "key expansion", tls::vec_concat(server_random.as_vector(), client_random.as_vector()), key_block_length);

        std::cout << "Keyblock:\n" << util::base16_encode(key_block) << "\n";

        size_t i = 0;
        auto client_mac_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.mac_key_length]};  i += cipher_param.mac_key_length;
        auto server_mac_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.mac_key_length]};  i += cipher_param.mac_key_length;
        auto client_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.key_length]};      i += cipher_param.key_length;
        auto server_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.key_length]};      i += cipher_param.key_length;
        auto client_iv      = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.fixed_iv_length]}; i += cipher_param.fixed_iv_length;
        auto server_iv      = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.fixed_iv_length]}; i += cipher_param.fixed_iv_length;
        assert(i == key_block.size());

        tls::cipher_parameters client_cipher_parameters{tls::cipher_parameters::encrypt, cipher_param, client_mac_key, client_enc_key, client_iv};
        tls::cipher_parameters server_cipher_parameters{tls::cipher_parameters::decrypt, cipher_param, server_mac_key, server_enc_key, server_iv};

        // TODO: This should obviously be reversed if running as a server
        pending_encrypt_cipher = tls::make_cipher(client_cipher_parameters);
        pending_decrypt_cipher = tls::make_cipher(server_cipher_parameters);
     }

    void send_change_cipher_spec() {
        if (!pending_encrypt_cipher) {
            FUNTLS_CHECK_FAILURE("Sending ChangeCipherSpec without a pending cipher suite");
        }
        send_record(tls::change_cipher_spec{});
        //
        // Immediately after sending [the ChangeCipherSpec] message, the sender MUST instruct the
        // record layer to make the write pending state the write active state.
        //
        encrypt_cipher = std::move(pending_encrypt_cipher);
        //
        // The sequence number MUST be set to zero whenever a connection state is made the
        // active state.
        //
        encrypt_sequence_number = 0;
        //
        // A Finished message is always sent immediately after a change
        // cipher spec message to verify that the key exchange and
        // authentication processes were successful
        //
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
        auto verify_data = tls::PRF(master_secret, "client finished", handshake_message_digest.result(), tls::finished::verify_data_length);
        assert(verify_data.size() == tls::finished::verify_data_length);

        std::vector<uint8_t> content;
        tls::append_to_buffer(content, tls::handshake_type::finished);
        tls::append_to_buffer(content, tls::uint24(verify_data.size()));
        tls::append_to_buffer(content, verify_data);

        handshake_message_digest.input(content); // Now safe to update since we've used 

        send_record(tls::content_type::handshake, content);
    }

    void send_record(tls::content_type content_type, const std::vector<uint8_t>& plaintext) {
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
        const auto ver_buffer = verification_buffer(encrypt_sequence_number++, content_type, current_protocol_version, plaintext.size());
        const auto fragment  = encrypt_cipher->process(plaintext, ver_buffer);
        FUNTLS_CHECK_BINARY(fragment.size(), <=, tls::record::max_ciphertext_length, "Illegal fragment size");

        std::vector<uint8_t> header;
        tls::append_to_buffer(header, content_type);
        tls::append_to_buffer(header, current_protocol_version);
        tls::append_to_buffer(header, tls::uint16(fragment.size()));
        assert(header.size() == 5);

        boost::asio::write(socket, boost::asio::buffer(header));
        boost::asio::write(socket, boost::asio::buffer(fragment));
    }

    void read_change_cipher_spec() {
        auto record = read_record();
        FUNTLS_CHECK_BINARY(record.type,            ==, tls::content_type::change_cipher_spec, "Invalid content type");
        FUNTLS_CHECK_BINARY(record.fragment.size(), ==, 1, "Invalid ChangeCipherSpec fragment size");
        FUNTLS_CHECK_BINARY(record.fragment[0],     !=, 0, "Invalid ChangeCipherSpec fragment data");
        std::cout << "Got ChangeCipherSpec\n";
        //
        // Reception of [the ChangeCipherSpec] message causes the receiver to instruct the record layer to
        // immediately copy the read pending state into the read current state.
        //
        if (!pending_decrypt_cipher) {
            FUNTLS_CHECK_FAILURE("Got ChangeCipherSpec without a pending cipher suite");
        }
        decrypt_cipher = std::move(pending_decrypt_cipher);
        decrypt_sequence_number = 0;
    }

    void read_finished() {
        const auto record = read_record();
        FUNTLS_CHECK_BINARY(record.type, ==, tls::content_type::handshake, "Invalid record type");
        const auto& content = record.fragment;
        // Parse content
        FUNTLS_CHECK_BINARY(content.size(), >=, 5, "Invalid finished message");
        FUNTLS_CHECK_BINARY(content[0], ==, (int)tls::handshake_type::finished, "Invalid finished message");
        FUNTLS_CHECK_BINARY(content[1], ==, 0, "Invalid finished message");
        FUNTLS_CHECK_BINARY(content[2], ==, 0, "Invalid finished message");
        FUNTLS_CHECK_BINARY(content[3], ==, tls::finished::verify_data_length, "Invalid finished message");
        FUNTLS_CHECK_BINARY(content.size(), ==, 4U + content[3], "Invalid finished message");
        const std::vector<uint8_t> verify_data{&content[4], &content[content.size()]};

        const auto calced_verify_data = tls::PRF(master_secret, "server finished", handshake_message_digest.result(), tls::finished::verify_data_length);
        if (verify_data != calced_verify_data) {
            std::ostringstream oss;
            oss << "Got invalid finished message. verify_data check failed. Expected ";
            oss << "'" << util::base16_encode(calced_verify_data) << "' Got";
            oss << "'" << util::base16_encode(verify_data);
            FUNTLS_CHECK_FAILURE(oss.str());
        }
    }

    tls::record read_record() {
        std::vector<uint8_t> buffer(5);
        boost::asio::read(socket, boost::asio::buffer(buffer));

        util::buffer_view buf_view{&buffer[0], buffer.size()};
        tls::content_type     content_type;
        tls::protocol_version protocol_version;
        tls::uint16           length;
        tls::from_bytes(content_type, buf_view);
        tls::from_bytes(protocol_version, buf_view);
        tls::from_bytes(length, buf_view);
        assert(buf_view.remaining() == 0);

        FUNTLS_CHECK_BINARY(protocol_version, ==, current_protocol_version, "Wrong TLS version");
        FUNTLS_CHECK_BINARY(length, >=, 1, "Illegal fragment size");
        FUNTLS_CHECK_BINARY(length, <=, tls::record::max_ciphertext_length, "Illegal fragment size");

        buffer.resize(length);
        boost::asio::read(socket, boost::asio::buffer(buffer));

        //
        // Decrypt
        //
        assert(buffer.size() <= tls::record::max_ciphertext_length);
        const auto ver_buffer = verification_buffer(decrypt_sequence_number++, content_type, current_protocol_version, 0 /* filled in later */);
        buffer = decrypt_cipher->process(buffer, ver_buffer);

        //
        // Decompression
        //
        // TODO: decompress buffer -> buffer
        FUNTLS_CHECK_BINARY(buffer.size(), <=, tls::record::max_compressed_length, "Illegal decoded fragment size");

        //
        // We now have a TLSPlaintext buffer for consumption
        //
        FUNTLS_CHECK_BINARY(buffer.size(), <=, tls::record::max_plaintext_length, "Illegal decoded fragment size");


        if (content_type == tls::content_type::alert) {
            util::buffer_view alert_buf(&buffer[0], buffer.size());
            tls::alert alert;
            tls::from_bytes(alert, alert_buf);
            FUNTLS_CHECK_BINARY(alert_buf.remaining(), ==, 0, "Invalid alert message");

            std::ostringstream oss;
            oss << alert.level << " " << alert.description;
            std::cout << "Got alert: " << oss.str() <<  std::endl;
            throw std::runtime_error("Alert received: " + oss.str());
        }

        return tls::record{content_type, protocol_version, std::move(buffer)};
    }
};

int main(int argc, char* argv[])
{
    if (argc != 2 && argc != 3) {
        std::cout << "Usage: " << argv[0] << " https-uri [cipher]\n";
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

    const std::string wanted_cipher_txt = argc >= 3 ? argv[2] : "rsa_with_aes_128_gcm_sha256";//"rsa_with_aes_256_cbc_sha256";
    tls::cipher_suite wanted_cipher = tls::cipher_suite::null_with_null_null;
    FUNTLS_CHECK_BINARY(bool(std::istringstream(wanted_cipher_txt)>>wanted_cipher), !=, false, "Invalid cipher " + wanted_cipher_txt);
    FUNTLS_CHECK_BINARY(wanted_cipher, !=, tls::cipher_suite::null_with_null_null, "Invalid cipher " + wanted_cipher_txt);


    std::cout << "Cipher suite: " << tls::parameters_from_suite(wanted_cipher) << std::endl;
    try {
        boost::asio::io_service         io_service;
        boost::asio::ip::tcp::socket    socket(io_service);
        boost::asio::ip::tcp::resolver  resolver(io_service);

        std::cout << "Connecting to " << host << ":" << port << " ..." << std::flush;
        boost::asio::connect(socket, resolver.resolve({host, port}));
        std::cout << " OK" << std::endl;
        tls_socket ts{socket};
        ts.perform_handshake(wanted_cipher);

        std::cout << "Completed handshake!\n";

        const auto data = "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n";
        ts.send_app_data(std::vector<uint8_t>(data.begin(), data.end()));

        // Ugly!
        bool got_app_data = false;
        for (;;) {
            try {
                const auto res = ts.next_app_data();
                std::cout << std::string(res.begin(), res.end()) << std::endl;
                got_app_data = true;
            } catch (const std::exception& e) {
                if (!got_app_data) throw;
                std::cout << e.what() << std::endl;
                break;
            }
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
