#include <iostream>
#include <cstdint>
#include <vector>
#include <string>

#include <boost/asio.hpp>

#include <hash/hash.h>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <aes/aes.h>
#include <rc4/rc4.h>
#include <3des/3des.h>
#include <util/base_conversion.h>
#include <util/test.h>
#include <util/buffer.h>
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

class cipher {
public:
    virtual ~cipher() {}
    virtual std::vector<uint8_t> process(const std::vector<uint8_t>& data) = 0;
};

class null_cipher : public cipher {
public:
    null_cipher() {}
    virtual std::vector<uint8_t> process(const std::vector<uint8_t>& data) override {
        return data;
    }
};

class rc4_cipher : public cipher {
public:
    explicit rc4_cipher(const std::vector<uint8_t>& key) : rc4_(key) {}

    virtual std::vector<uint8_t> process(const std::vector<uint8_t>& data) override {
        auto buffer = data;
        rc4_.process(buffer);
        return buffer;
    }
private:
    rc4::rc4 rc4_;
};

class _3des_cipher : public cipher {
public:
    static_assert(_3des_traits::fixed_iv_length == 0, "");
    static constexpr size_t iv_length = _3des_traits::record_iv_length;

    enum operation { decrypt = 0, encrypt = 1 };
    explicit _3des_cipher(operation op, const std::vector<uint8_t>& key) : operation_(op), key_(key) {
    }

    // TODO: Unify GenericBlockCipher stuff with aes_cipher
    virtual std::vector<uint8_t> process(const std::vector<uint8_t>& data) override {
        if (operation_ == decrypt) {
            FUNTLS_CHECK_BINARY(data.size(), >, iv_length, "Message too small");
            // Extract initialization vector
            const std::vector<uint8_t> iv(&data[0],&data[iv_length]);
            const std::vector<uint8_t> encrypted(&data[iv_length],&data[data.size()]);
            return _3des::_3des_decrypt_cbc(key_, iv, encrypted);
        } else {
            assert(operation_ == encrypt);
            // Generate initialization vector
            std::vector<uint8_t> message(iv_length);
            tls::get_random_bytes(&message[0], message.size());
            tls::append_to_buffer(message, _3des::_3des_encrypt_cbc(key_, message, data));
            return message;
        }
    }
private:
    operation            operation_;
    std::vector<uint8_t> key_;

};

class aes_cbc_cipher : public cipher {
public:
    static constexpr size_t iv_length = aes_cbc_traits<256>::record_iv_length;
    static_assert(aes_cbc_traits<256>::fixed_iv_length == 0, "");
    static_assert(aes_cbc_traits<256>::fixed_iv_length == aes_cbc_traits<128>::fixed_iv_length, "");
    static_assert(aes_cbc_traits<256>::record_iv_length == aes_cbc_traits<128>::record_iv_length, "");

    enum operation { decrypt = 0, encrypt = 1 };
    explicit aes_cbc_cipher(operation op, const std::vector<uint8_t>& key) : operation_(op), key_(key) {}

    //
    // A GenericBlockCipher consist of the initialization vector and block-ciphered
    // content, mac and padding.
    //

    virtual std::vector<uint8_t> process(const std::vector<uint8_t>& data) override {
        if (operation_ == decrypt) {
            FUNTLS_CHECK_BINARY(data.size(), >, iv_length, "Message too small");
            // Extract initialization vector
            const std::vector<uint8_t> iv(&data[0],&data[iv_length]);
            const std::vector<uint8_t> encrypted(&data[iv_length],&data[data.size()]);
            return aes::aes_decrypt_cbc(key_, iv, encrypted);
        } else {
            assert(operation_ == encrypt);
            // Generate initialization vector
            std::vector<uint8_t> message(iv_length);
            tls::get_random_bytes(&message[0], message.size());
            tls::append_to_buffer(message, aes::aes_encrypt_cbc(key_, message, data));
            return message;
        }
    }
private:
    operation            operation_;
    std::vector<uint8_t> key_;
};


class aes_gcm_cipher : public cipher {
public:
    static constexpr size_t fixed_iv_length  = aes_gcm_traits<256>::fixed_iv_length;
    static constexpr size_t record_iv_length = aes_gcm_traits<256>::record_iv_length;
    static_assert(fixed_iv_length == 4, "");
    static_assert(record_iv_length == 8, "");
    static_assert(aes_gcm_traits<256>::fixed_iv_length == aes_gcm_traits<128>::fixed_iv_length, "");
    static_assert(aes_gcm_traits<256>::record_iv_length == aes_gcm_traits<128>::record_iv_length, "");

    enum operation { decrypt = 0, encrypt = 1 };
    explicit aes_gcm_cipher(operation op, const std::vector<uint8_t>& key, const std::vector<uint8_t>& salt) : operation_(op), key_(key), salt_(salt) {
        assert(salt.size() == fixed_iv_length);
    }

    virtual std::vector<uint8_t> process(const std::vector<uint8_t>& data) override {
        std::cerr << __PRETTY_FUNCTION__ << " not implemented correctly\n";
        std::vector<uint8_t> A;
        if (operation_ == decrypt) {
            std::vector<uint8_t> T;
            FUNTLS_CHECK_BINARY(data.size(), >, record_iv_length, "Message too small");
            // Extract initialization vector
            std::vector<uint8_t> iv = salt_;
            tls::append_to_buffer(iv, std::vector<uint8_t>(&data[0],&data[record_iv_length]));
            assert(iv.size() == fixed_iv_length + record_iv_length);
            const std::vector<uint8_t> encrypted(&data[record_iv_length],&data[data.size()]);
            return aes::aes_decrypt_gcm(key_, iv, encrypted, A, T);
        } else {
            assert(operation_ == encrypt);
            // Generate initialization vector
            std::vector<uint8_t> message(record_iv_length);
            tls::get_random_bytes(&message[0], message.size());
            std::vector<uint8_t> iv = salt_;
            tls::append_to_buffer(iv, message);
            auto res = aes::aes_encrypt_gcm(key_, iv, data, A);
            tls::append_to_buffer(message, res.first); // C
            //T = res.second;
            return message;
        }
    }
private:
    operation            operation_;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> salt_;
};

} } // namespace funtls::tls

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
    static constexpr size_t         master_secret_size = 48;

    const tls::protocol_version     current_protocol_version = tls::protocol_version_tls_1_2;
    tls::cipher_suite               wanted_cipher;
    tls::cipher_suite               current_cipher           = tls::cipher_suite::null_with_null_null;

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
    uint64_t                        sequence_number = 0; // TODO: A seperate sequence number is used for each connection end

    std::vector<uint8_t>            client_mac_key;
    std::vector<uint8_t>            server_mac_key;

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

        // HAX
        if (dhe_kex) {
            std::cout << "Verifying server DHE signature\n";
            FUNTLS_CHECK_BINARY(dhe_kex->signature_algorithm, ==, tls::signature_algorithm::rsa, "");
            const auto digest = x509::pkcs1_decode(*server_public_key, dhe_kex->signature.as_vector());
            FUNTLS_CHECK_BINARY(x509::id_sha1,             ==, digest.digest_algorithm, "");
            FUNTLS_CHECK_BINARY(tls::hash_algorithm::sha1, ==, dhe_kex->hash_algorithm, "");
            std::cout << "Digest (Algorithm: " << digest.digest_algorithm << ")\n" << util::base16_encode(digest.digest) << std::endl;

            std::vector<uint8_t> digest_buf;
            append_to_buffer(digest_buf, client_random);
            append_to_buffer(digest_buf, server_random);
            append_to_buffer(digest_buf, dhe_kex->params);
            const auto calced_digest = hash::sha1{}.input(digest_buf).result();
            std::cout << "Calculated digest: " << util::base16_encode(calced_digest) << std::endl;

            FUNTLS_CHECK_BINARY(calced_digest.size(), ==, digest.digest.size(), "Wrong digest size");
            if (!std::equal(calced_digest.begin(), calced_digest.end(), digest.digest.begin())) {
                throw std::runtime_error("Digest mismatch in " + std::string(__PRETTY_FUNCTION__) + " Calculated: " +
                        util::base16_encode(calced_digest) + " Expected: " +
                        util::base16_encode(digest.digest));
            }

            server_dh_params.reset(new tls::server_dh_params(dhe_kex->params));
        }
    }

    std::vector<uint8_t> rsa_client_kex_data(const std::vector<uint8_t>& pre_master_secret) const {
        assert(server_public_key);
        const auto& s_pk = *server_public_key;
        const auto n = s_pk.modolus.as<int_type>();
        const auto e = s_pk.public_exponent.as<int_type>();

        // Perform RSAES-PKCS1-V1_5-ENCRYPT (http://tools.ietf.org/html/rfc3447 7.2.1)

        // Get k=message length
        const size_t k = s_pk.key_length();

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
        //std::cout << "m (" << EM.size() << ") = " << util::base16_encode(EM) << std::dec << "\n";

        // 3.b
        const int_type c = powm(m, e, n); // c = RSAEP ((n, e), m)
        //std::cout << "c:\n" << c << std::endl;

        // 3.c Convert the ciphertext representative c to a ciphertext C of length k octets
        // C = I2OSP (c, k)
        const auto C = x509::base256_encode(c, k);
        //std::cout << "C:\n" << util::base16_encode(C) << std::endl;

        return C;
    }

    std::vector<uint8_t> send_client_key_exchange_rsa() {
        // OK, now it's time to do ClientKeyExchange
        // Since we're doing RSA, we'll be sending the EncryptedPreMasterSecret

        // Prepare pre-master secret (version + 46 random bytes)
        std::vector<uint8_t> pre_master_secret(master_secret_size);
        pre_master_secret[0] = current_protocol_version.major;
        pre_master_secret[1] = current_protocol_version.minor;
        tls::get_random_bytes(&pre_master_secret[2], pre_master_secret.size()-2);

        std::cout << "Pre-master secret: " << util::base16_encode(&pre_master_secret[2], pre_master_secret.size()-2) << std::endl;

        const auto C = rsa_client_kex_data(pre_master_secret);
        tls::client_key_exchange_rsa client_key_exchange{tls::vector<tls::uint8,0,(1<<16)-1>{C}};
        send_record(make_handshake(client_key_exchange));
        return pre_master_secret;
    }

    std::vector<uint8_t> send_client_key_exchange_dhe_rsa() {
        const size_t key_size = server_dh_params->dh_p.size();
        std::cout << "Should generate int of size " << key_size*8 << " bits " << std::endl;
        std::vector<uint8_t> rand_int(key_size);
        do {
            tls::get_random_bytes(&rand_int[0], rand_int.size());
        } while (std::find_if(rand_int.begin(), rand_int.end(), [](uint8_t i) { return i != 0; }) == rand_int.end());

        const int_type private_key = x509::base256_decode<int_type>(rand_int);

        std::cout << "DHE client private key: " << std::hex << private_key << std::dec << std::endl;

        const int_type p  = x509::base256_decode<int_type>(server_dh_params->dh_p.as_vector());
        const int_type g  = x509::base256_decode<int_type>(server_dh_params->dh_g.as_vector());
        const int_type Ys = x509::base256_decode<int_type>(server_dh_params->dh_Ys.as_vector());
        const int_type Yc = powm(g, private_key, p);
        const auto dh_Yc  = x509::base256_encode(Yc, key_size);

        std::cout << "dh_Yc = " << util::base16_encode(dh_Yc) << std::endl;

        tls::client_key_exchange_dhe_rsa client_key_exchange{tls::vector<tls::uint8,1,(1<<16)-1>{dh_Yc}};
        send_record(make_handshake(client_key_exchange));

        const int_type Z = powm(Ys, private_key, p);
        const auto dh_Z  = x509::base256_encode(Z, key_size);
        std::cout << "Negotaited key = " << util::base16_encode(dh_Z) << std::endl;
        return dh_Z;
    }

    void send_client_key_exchange() {
        const auto cipher_param = tls::parameters_from_suite(wanted_cipher);
        std::vector<uint8_t> pre_master_secret;
        if (cipher_param.key_exchange_algorithm == tls::key_exchange_algorithm::rsa) {
            pre_master_secret = send_client_key_exchange_rsa();
        } else if (cipher_param.key_exchange_algorithm == tls::key_exchange_algorithm::dhe_rsa) {
            assert(server_dh_params);
            pre_master_secret = send_client_key_exchange_dhe_rsa();
        } else {
            FUNTLS_CHECK_FAILURE("Internal error: Unsupported KeyExchangeAlgorithm " + std::to_string((int)(cipher_param.key_exchange_algorithm)));
        }
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
        const size_t key_block_length  = 2 * cipher_param.mac_key_length + 2 * cipher_param.key_length + 2 * cipher_param.fixed_iv_length;
        auto key_block = tls::PRF(master_secret, "key expansion", tls::vec_concat(server_random.as_vector(), client_random.as_vector()), key_block_length);

        size_t i = 0;
        client_mac_key      = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.mac_key_length]}; i += cipher_param.mac_key_length;
        server_mac_key      = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.mac_key_length]}; i += cipher_param.mac_key_length;
        auto client_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.key_length]}; i += cipher_param.key_length;
        auto server_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.key_length]}; i += cipher_param.key_length;

        // TODO: FIXME: handle ConnectionEnd stuff
        if (cipher_param.bulk_cipher_algorithm == tls::bulk_cipher_algorithm::rc4) {
            encrypt_cipher.reset(new tls::rc4_cipher(client_enc_key));
            decrypt_cipher.reset(new tls::rc4_cipher(server_enc_key));
        } else if (cipher_param.bulk_cipher_algorithm == tls::bulk_cipher_algorithm::_3des) {
            encrypt_cipher.reset(new tls::_3des_cipher(tls::_3des_cipher::encrypt, client_enc_key));
            decrypt_cipher.reset(new tls::_3des_cipher(tls::_3des_cipher::decrypt, server_enc_key));
        } else if (cipher_param.bulk_cipher_algorithm == tls::bulk_cipher_algorithm::aes_cbc) {
            encrypt_cipher.reset(new tls::aes_cbc_cipher(tls::aes_cbc_cipher::encrypt, client_enc_key));
            decrypt_cipher.reset(new tls::aes_cbc_cipher(tls::aes_cbc_cipher::decrypt, server_enc_key));
        } else if (cipher_param.bulk_cipher_algorithm == tls::bulk_cipher_algorithm::aes_gcm) {
            auto client_iv = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.fixed_iv_length]}; i += cipher_param.fixed_iv_length;
            auto server_iv = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.fixed_iv_length]}; i += cipher_param.fixed_iv_length;
            assert(cipher_param.cipher_type == tls::cipher_type::aead);
            encrypt_cipher.reset(new tls::aes_gcm_cipher(tls::aes_gcm_cipher::encrypt, client_enc_key, client_iv));
            decrypt_cipher.reset(new tls::aes_gcm_cipher(tls::aes_gcm_cipher::decrypt, server_enc_key, server_iv));
        } else {
            FUNTLS_CHECK_FAILURE("Unsupported bulk_cipher_algorithm: " + std::to_string((int)cipher_param.bulk_cipher_algorithm));
        }
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
        if (block_length) {
            assert(cipher_param.cipher_type == tls::cipher_type::block);
            uint8_t padding_length = block_length - (content_and_mac.size()+1) % block_length;
            for (unsigned i = 0; i < padding_length + 1U; ++i) {
                content_and_mac.push_back(padding_length);
            }
            assert(content_and_mac.size() % block_length == 0);
        } else {
            assert(cipher_param.cipher_type == tls::cipher_type::stream);
        }

        auto fragment = encrypt_cipher->process(content_and_mac);

        assert(fragment.size() < ((1<<14)+2048) && "Payload of TLSCiphertext MUST NOT exceed 2^14 + 2048");
        return fragment;
    }

    // HACK HACK HACK FIXME TODO XXX
    std::unique_ptr<tls::cipher> encrypt_cipher = std::unique_ptr<tls::cipher>(new tls::null_cipher{});
    std::unique_ptr<tls::cipher> decrypt_cipher = std::unique_ptr<tls::cipher>(new tls::null_cipher{});

    std::vector<uint8_t> bulk_decrypt(const std::vector<uint8_t>& dec_key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& content) {
        const auto cipher_param = tls::parameters_from_suite(current_cipher);
        if (cipher_param.bulk_cipher_algorithm == tls::bulk_cipher_algorithm::rc4) {
        } else if (cipher_param.bulk_cipher_algorithm == tls::bulk_cipher_algorithm::aes_cbc) {
            return aes::aes_decrypt_cbc(dec_key, iv, content);
        } else {
            assert(cipher_param.bulk_cipher_algorithm == tls::bulk_cipher_algorithm::null);
        }
        return content;
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

    void decrypt(tls::content_type record_type, std::vector<uint8_t>& buffer) {
        assert(buffer.size() <= tls::record::max_ciphertext_length);

        // TODO: improve really lazy parsing/validation
        const auto cipher_param = tls::parameters_from_suite(current_cipher);

        FUNTLS_CHECK_BINARY(buffer.size(), >=, cipher_param.record_iv_length, "Message too small"); // needs work..

        const auto decrypted = decrypt_cipher->process(buffer);

        // check padding
        size_t padding_length = 0;
        size_t mac_index = 0;
        if (cipher_param.cipher_type == tls::cipher_type::block) {
            // TODO: FIX
            padding_length = decrypted[decrypted.size()-1];
            mac_index = decrypted.size()-1-padding_length-cipher_param.mac_length;
            assert(decrypted.size() % cipher_param.block_length == 0);
            assert(padding_length + 1U < decrypted.size()); // Padding+Padding length byte musn't be sole contents
            for (unsigned i = 0; i < padding_length; ++i) assert(decrypted[decrypted.size()-1-padding_length] == padding_length);
        } else {
            assert(cipher_param.cipher_type == tls::cipher_type::stream);
            mac_index = decrypted.size()-cipher_param.mac_length;
        }

        // Extract MAC + Content
        const std::vector<uint8_t> mac{&decrypted[mac_index],&decrypted[mac_index+cipher_param.mac_length]};

        const std::vector<uint8_t> content{&decrypted[0],&decrypted[mac_index]};

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
        //std::cout << "MAC\n" << util::base16_encode(mac) << std::endl;
        //std::cout << "Calculated MAC\n" << util::base16_encode(calced_mac) << std::endl;
        //std::cout << "Content\n" << util::base16_encode(content) << std::endl;
        assert(calced_mac == mac);

        sequence_number++;

        buffer = std::move(content);
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

    const std::string wanted_cipher_txt = argc >= 3 ? argv[2] : "rsa_with_aes_256_cbc_sha256";
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

        const auto data = "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n";
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
