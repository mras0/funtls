#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

#include <boost/asio.hpp>

#include <hash/hash.h>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <x509/x509_ec.h>
#include <x509/x509_io.h>
#include <util/base_conversion.h>
#include <util/test.h>
#include <util/buffer.h>
#include <util/int_util.h>
#include <tls/tls.h>
#include <tls/tls_ecc.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

namespace {

template<typename IntType>
IntType rand_positive_int_less(const IntType& n) {
    const auto byte_count = ilog256(n);
    assert(byte_count != 0);
    std::vector<uint8_t> bytes(byte_count);
    IntType res;
    do {
        tls::get_random_bytes(&bytes[0], bytes.size());
        res = be_uint_from_bytes<IntType>(bytes);
    } while (res == 0 || res >= n);
    return res;
}

tls::hash_algorithm hash_algorithm_from_oid(const asn1::object_id& oid) {
    if (oid == x509::id_md5) return tls::hash_algorithm::md5;
    if (oid == x509::id_sha1) return tls::hash_algorithm::sha1;
    if (oid == x509::id_sha256) return tls::hash_algorithm::sha256;
    if (oid == x509::id_sha384) return tls::hash_algorithm::sha384;
    if (oid == x509::id_sha512) return tls::hash_algorithm::sha512;
    std::ostringstream msg;
    msg << "Unknown hash algorithm " << oid;
    FUNTLS_CHECK_FAILURE(msg.str());
}

class client_key_exchange_protocol {
public:
    typedef std::pair<std::vector<uint8_t>, tls::handshake> result_type;

    virtual ~client_key_exchange_protocol() {}

    result_type result() const {
        return do_result();
    }

    void certificate_list(const std::vector<x509::certificate>& certificate_list) {
        assert(!server_certificate_);
        assert(!certificate_list.empty());
        server_certificate_.reset(new x509::certificate(certificate_list.front()));
    }

    void server_key_exchange(const tls::handshake& ske) {
        do_server_key_exchange(ske);
    }

protected:
    const x509::certificate& server_certificate() const {
        if (!server_certificate_) FUNTLS_CHECK_FAILURE("No server certificate provided");
        return *server_certificate_;
    }

private:
    std::unique_ptr<x509::certificate> server_certificate_;

    virtual result_type do_result() const = 0;
    virtual void do_server_key_exchange(const tls::handshake&) {
        FUNTLS_CHECK_FAILURE("Not expecting ServerKeyExchange message");
    }
};

class rsa_client_kex_protocol : public client_key_exchange_protocol {
public:
    rsa_client_kex_protocol(tls::protocol_version protocol_version)
        : protocol_version_(protocol_version) {
    }

private:
    tls::protocol_version protocol_version_;

    virtual result_type do_result() const override {
        auto server_pk = rsa_public_key_from_certificate(server_certificate());
        // OK, now it's time to do ClientKeyExchange
        // Since we're doing RSA, we'll be sending the EncryptedPreMasterSecret
        // Prepare pre-master secret (version + 46 random bytes)
        std::vector<uint8_t> pre_master_secret(tls::master_secret_size);
        pre_master_secret[0] = protocol_version_.major;
        pre_master_secret[1] = protocol_version_.minor;
        tls::get_random_bytes(&pre_master_secret[2], pre_master_secret.size()-2);

        const auto C = x509::pkcs1_encode(server_pk, pre_master_secret, &tls::get_random_bytes);
        tls::client_key_exchange_rsa client_key_exchange{tls::vector<tls::uint8,0,(1<<16)-1>{C}};
        return std::make_pair(std::move(pre_master_secret), make_handshake(client_key_exchange));
    }
};

void verify_signature_rsa(const x509::certificate& cert, const tls::signed_signature& sig, const std::vector<uint8_t>& digest_buf)
{
    std::cout << "Verify RSA " << sig.hash_algorithm << " signature" << std::endl;
    auto public_key = rsa_public_key_from_certificate(cert);
    FUNTLS_CHECK_BINARY(sig.signature_algorithm, ==, tls::signature_algorithm::rsa, "");
    const auto digest = x509::pkcs1_decode(public_key, sig.value.as_vector());
    FUNTLS_CHECK_BINARY(digest.digest_algorithm.null_parameters(), ==, true, "Invalid algorithm parameters");
    FUNTLS_CHECK_BINARY(hash_algorithm_from_oid(digest.digest_algorithm.id()), ==, sig.hash_algorithm, "");

    const auto calced_digest = tls::get_hash(sig.hash_algorithm).input(digest_buf).result();
    FUNTLS_CHECK_BINARY(calced_digest.size(), ==, digest.digest.size(), "Wrong digest size");
    if (!std::equal(calced_digest.begin(), calced_digest.end(), digest.digest.begin())) {
        throw std::runtime_error("Digest mismatch in " + std::string(__PRETTY_FUNCTION__) + " Calculated: " +
                util::base16_encode(calced_digest) + " Expected: " +
                util::base16_encode(digest.digest));
    }
}

class dhe_rsa_client_kex_protocol : public client_key_exchange_protocol {
public:
    dhe_rsa_client_kex_protocol(const tls::random& client_random, const tls::random& server_random) {
        tls::append_to_buffer(digest_buf, client_random);
        tls::append_to_buffer(digest_buf, server_random);
    }

private:
    std::unique_ptr<tls::server_dh_params> server_dh_params_;
    std::vector<uint8_t> digest_buf;

    virtual void do_server_key_exchange(const tls::handshake& ske) override {
        assert(!server_dh_params_);
        auto kex = tls::get_as<tls::server_key_exchange_dhe>(ske);
        tls::append_to_buffer(digest_buf, kex.params);
        verify_signature_rsa(server_certificate(), kex.signature, digest_buf);
        server_dh_params_.reset(new tls::server_dh_params(kex.params));
    }

    virtual result_type do_result() const override {
        if (!server_dh_params_) FUNTLS_CHECK_FAILURE("");
        const int_type p  = x509::base256_decode<int_type>(server_dh_params_->dh_p.as_vector());
        const int_type g  = x509::base256_decode<int_type>(server_dh_params_->dh_g.as_vector());
        const int_type Ys = x509::base256_decode<int_type>(server_dh_params_->dh_Ys.as_vector());
        const size_t key_size = server_dh_params_->dh_p.size();
        const int_type private_key = rand_positive_int_less(p);

        //std::cout << "DHE client private key: " << std::hex << private_key << std::dec << std::endl;

        const int_type Yc = powm(g, private_key, p);
        const auto dh_Yc  = x509::base256_encode(Yc, key_size);

        //std::cout << "dh_Yc = " << util::base16_encode(dh_Yc) << std::endl;

        tls::client_key_exchange_dhe_rsa client_key_exchange{dh_Yc};
        auto handshake = make_handshake(client_key_exchange);

        const int_type Z = powm(Ys, private_key, p);
        auto dh_Z  = x509::base256_encode(Z, key_size);
        //std::cout << "Negotaited key = " << util::base16_encode(dh_Z) << std::endl;
        return std::make_pair(std::move(dh_Z), std::move(handshake));
    }
};

void verify_signature_ecdsa(const x509::certificate& cert, const tls::signed_signature& sig, const std::vector<uint8_t>& digest_buf)
{
    std::cout << "Verify ECDSA " << sig.hash_algorithm << " signature" << std::endl;
    auto public_key = x509::ec_public_key_from_certificate(cert);
    const auto& curve = x509::curve_from_name(public_key.curve_name);

    FUNTLS_CHECK_BINARY(tls::signature_algorithm::ecdsa, ==, sig.signature_algorithm, "Invalid key exchange algorithm");
    const auto ecdsa_sig = x509::ecdsa_sig_value::parse(sig.value.as_vector());
    auto H = tls::get_hash(sig.hash_algorithm).input(digest_buf).result();
    const auto max_size = ilog256(curve.n);
    if (H.size() > max_size) {
        H.erase(H.begin() + max_size, H.end());
    }
    const auto e = x509::base256_decode<ec::field_elem>(H);

    assert(e >= 0 && e < curve.n);
    curve.verify_ecdsa_signature(public_key.Q, ecdsa_sig.r, ecdsa_sig.s, e);
}

class ecdhe_client_kex_protocol : public client_key_exchange_protocol {
public:
    ecdhe_client_kex_protocol(tls::signature_algorithm sig_algo, const tls::random& client_random, const tls::random& server_random) {
        tls::append_to_buffer(digest_buf_, client_random);
        tls::append_to_buffer(digest_buf_, server_random);
        if (sig_algo == tls::signature_algorithm::rsa) {
            verify_signature_ = &verify_signature_rsa;
        } else if (sig_algo == tls::signature_algorithm::ecdsa) {
            verify_signature_ = &verify_signature_ecdsa;
        } else {
            std::ostringstream msg;
            msg << "Unsupported signature algorithm " << sig_algo;
            FUNTLS_CHECK_FAILURE(msg.str());
        }
    }

private:
    struct params {
        tls::named_curve curve_name;
        ec::point        Q;
    };
    std::unique_ptr<params>         params_;
    std::vector<uint8_t>            digest_buf_;
    decltype(verify_signature_rsa)* verify_signature_;

    virtual void do_server_key_exchange(const tls::handshake& ske) override {
        assert(params_ == nullptr);
        auto kex = tls::get_as<tls::server_key_exchange_ec_dhe>(ske);
        std::cout << "curve_type=" << kex.params.curve_params.curve_type << std::endl;
        FUNTLS_CHECK_BINARY(kex.params.curve_params.curve_type, ==, tls::ec_curve_type::named_curve, "Unsupported curve type");
        std::cout << "named_curve=" << kex.params.curve_params.named_curve << std::endl;
        const auto& curve = tls::curve_from_name(kex.params.curve_params.named_curve);
        const auto ephemeral_public_key = ec::point_from_bytes(kex.params.public_key.as_vector());
        std::cout << "ephemeral_public_key=" << ephemeral_public_key << std::endl;
        curve.check_public_key(ephemeral_public_key);
        tls::append_to_buffer(digest_buf_, kex.params);
        verify_signature_(server_certificate(), kex.signature, digest_buf_);
        params_.reset(new params{kex.params.curve_params.named_curve, ephemeral_public_key});
    }

    virtual result_type do_result() const override {
        if (!params_) FUNTLS_CHECK_FAILURE("");
        const auto& curve = tls::curve_from_name(params_->curve_name);

        const size_t size = ilog256(curve.n);
        std::cout << "size = " << size << std::endl;
        assert(size == ilog256(curve.p));

        const auto d_U = rand_positive_int_less(curve.n); // private key
        assert(d_U >= 1);
        assert(d_U < curve.n);

        ec::point Yc = curve.mul(d_U, curve.G); // ephemeral client public key
        std::cout << "Client public key: " << Yc << std::endl;
#ifndef NDEBUG
        curve.check_public_key(Yc);
#endif

        ec::point P = curve.mul(d_U, params_->Q);  // shared secret
        assert(curve.on_curve(P));

        std::cout << "Shared secret: " << P << std::endl;

        FUNTLS_CHECK_BINARY(P, !=, ec::infinity, "Invalid shared secret obtained");

        // Make handshake with client public key
        assert(Yc.x < curve.p);
        assert(Yc.x < curve.n);
        assert(Yc.x < (ec::field_elem(1)<<(8*size)));
        assert(Yc.y < curve.p);
        assert(Yc.y < curve.n);
        assert(Yc.y < (ec::field_elem(1)<<(8*size)));
        auto handshake = tls::make_handshake(tls::client_key_exchange_ecdhe_ecdsa{ec::point_to_bytes(Yc, size)});

        // z: shared secret
        const auto& z = P.x;

        // Return shared secret and handshake
        assert(z < curve.p);
        assert(z < curve.n);
        assert(z < (ec::field_elem(1)<<(8*size)));
        return std::make_pair(x509::base256_encode(z, size), std::move(handshake));
    }

};

} // unnamed namespace

namespace funtls { namespace tls {

enum class connection_end { server, client };

// TODO: Handle record fragmentation/coalescence
class socket {
public:
    void send_app_data(const std::vector<uint8_t>& d) {
        send_record(content_type::application_data, d);
    }

    std::vector<uint8_t> next_app_data() {
        const auto record = read_record();
        FUNTLS_CHECK_BINARY(record.type, ==, content_type::application_data, "Unexpected content type");
        return record.fragment;
    }

protected:
    explicit socket(connection_end ce, boost::asio::ip::tcp::socket&& socket)
        : socket_(std::move(socket))
        , connection_end_(ce) {
    }

    void send_record(tls::content_type content_type, const std::vector<uint8_t>& plaintext) {
        collapse_pending();
        FUNTLS_CHECK_BINARY(plaintext.size(), >=, 1, "Illegal plain text size"); // TODO: Empty plaintext is legal for app data
        FUNTLS_CHECK_BINARY(plaintext.size(), <=, record::max_plaintext_length, "Illegal plain text size");

        if (content_type == tls::content_type::handshake) {
            append_to_buffer(handshake_messages_, plaintext);
        }

        // Compression would happen here

        // Do encryption
        const auto ver_buffer = verification_buffer(encrypt_sequence_number_++, content_type, current_protocol_version_, plaintext.size());
        const auto fragment  = encrypt_cipher_->process(plaintext, ver_buffer);
        FUNTLS_CHECK_BINARY(fragment.size(), <=, record::max_ciphertext_length, "Illegal fragment size");

        std::vector<uint8_t> header;
        append_to_buffer(header, content_type);
        append_to_buffer(header, current_protocol_version_);
        append_to_buffer(header, uint16(fragment.size()));
        assert(header.size() == 5);

        boost::asio::write(socket_, boost::asio::buffer(header));
        boost::asio::write(socket_, boost::asio::buffer(fragment));
    }

    record read_record() {
        collapse_pending();
        std::vector<uint8_t> buffer(5);
        boost::asio::read(socket_, boost::asio::buffer(buffer));

        util::buffer_view     buf_view{&buffer[0], buffer.size()};
        content_type     content_type;
        protocol_version protocol_version;
        uint16           length;
        from_bytes(content_type, buf_view);
        from_bytes(protocol_version, buf_view);
        from_bytes(length, buf_view);
        assert(buf_view.remaining() == 0);

        FUNTLS_CHECK_BINARY(protocol_version, ==, current_protocol_version(), "Wrong TLS version");
        FUNTLS_CHECK_BINARY(length, >=, 1, "Illegal fragment size");
        FUNTLS_CHECK_BINARY(length, <=, record::max_ciphertext_length, "Illegal fragment size");

        buffer.resize(length);
        assert(buffer.size() <= record::max_ciphertext_length);
        boost::asio::read(socket_, boost::asio::buffer(buffer));

        //
        // Decrypt
        //
        const auto ver_buffer = verification_buffer(decrypt_sequence_number_++, content_type, current_protocol_version(), 0 /* filled in later */);
        buffer = decrypt_cipher_->process(buffer, ver_buffer);

        // Decompression would happen here
        FUNTLS_CHECK_BINARY(buffer.size(), <=, record::max_compressed_length, "Illegal decoded fragment size");

        //
        // We now have a TLSPlaintext buffer for consumption
        //
        FUNTLS_CHECK_BINARY(buffer.size(), <=, record::max_plaintext_length, "Illegal decoded fragment size");

        if (content_type == tls::content_type::alert) {
            util::buffer_view alert_buf(&buffer[0], buffer.size());
            alert alert;
            from_bytes(alert, alert_buf);
            FUNTLS_CHECK_BINARY(alert_buf.remaining(), ==, 0, "Invalid alert message");

            std::ostringstream oss;
            oss << alert.level << " " << alert.description;
            std::cout << "Got alert: " << oss.str() <<  std::endl;
            throw std::runtime_error("Alert received: " + oss.str());
        }

        if (content_type == tls::content_type::handshake) {
            assert(pending_handshake_messages_.empty());
            pending_handshake_messages_ = buffer; // Will not become actove after this message has been parsed. This is a HACK
        }

        return record{content_type, protocol_version, std::move(buffer)};
    }

    void send_handshake(const handshake& handshake) {
        assert(handshake.content_type == content_type::handshake);
        std::vector<uint8_t> payload_buffer;
        append_to_buffer(payload_buffer, handshake);

        send_record(handshake.content_type, payload_buffer);
    }

    handshake read_handshake() {
        auto record = read_record();
        FUNTLS_CHECK_BINARY(record.type, ==, content_type::handshake, "Invalid content type");

        util::buffer_view frag_buf{&record.fragment[0], record.fragment.size()};
        handshake handshake;
        from_bytes(handshake, frag_buf);
        if (frag_buf.remaining()) {
            FUNTLS_CHECK_FAILURE("Unread handshake data. Fragment: " + util::base16_encode(record.fragment));
        }
        return handshake;
    }

    protocol_version current_protocol_version() const {
        return current_protocol_version_;
    }

    std::vector<uint8_t> handshake_messages() const {
        return handshake_messages_;
    }

    void set_pending_ciphers(cipher_parameters&& client_cipher_parameters, cipher_parameters&& server_cipher_parameters) {
        assert(!pending_encrypt_cipher_ && !pending_decrypt_cipher_);
        pending_encrypt_cipher_ = make_cipher(client_cipher_parameters);
        pending_decrypt_cipher_ = make_cipher(server_cipher_parameters);
    }

    void send_change_cipher_spec() {
        std::cout << "Sending change cipher spec." << std::endl;
        if (!pending_encrypt_cipher_) {
            FUNTLS_CHECK_FAILURE("Sending ChangeCipherSpec without a pending cipher suite");
        }
        change_cipher_spec msg{};
        std::vector<uint8_t> payload_buffer;
        append_to_buffer(payload_buffer, msg);
        send_record(msg.content_type, payload_buffer);
        //
        // Immediately after sending [the ChangeCipherSpec] message, the sender MUST instruct the
        // record layer to make the write pending state the write active state.
        //
        encrypt_cipher_ = std::move(pending_encrypt_cipher_);
        //
        // The sequence number MUST be set to zero whenever a connection state is made the
        // active state.
        //
        encrypt_sequence_number_ = 0;
        //
        // A Finished message is always sent immediately after a change
        // cipher spec message to verify that the key exchange and
        // authentication processes were successful
        //
        send_handshake(tls::make_handshake(tls::finished{do_verify_data(connection_end_)}));
    }

    void read_change_cipher_spec() {
        auto record = read_record();
        FUNTLS_CHECK_BINARY(record.type,            ==, content_type::change_cipher_spec, "Invalid content type");
        FUNTLS_CHECK_BINARY(record.fragment.size(), ==, 1, "Invalid ChangeCipherSpec fragment size");
        FUNTLS_CHECK_BINARY(record.fragment[0],     !=, 0, "Invalid ChangeCipherSpec fragment data");
        //
        // Reception of [the ChangeCipherSpec] message causes the receiver to instruct the record layer to
        // immediately copy the read pending state into the read current state.
        //
        if (!pending_decrypt_cipher_) {
            FUNTLS_CHECK_FAILURE("Got ChangeCipherSpec without a pending cipher suite");
        }
        decrypt_cipher_          = std::move(pending_decrypt_cipher_);
        decrypt_sequence_number_ = 0;

        // Read finished
        auto handshake = read_handshake();
        auto finished = tls::get_as<tls::finished>(handshake);
        const auto calced_verify_data = do_verify_data(connection_end_ == connection_end::server ? connection_end::client : connection_end::server);
        if (finished.verify_data != calced_verify_data) {
            std::ostringstream oss;
            oss << "Got invalid finished message. verify_data check failed. Expected ";
            oss << "'" << util::base16_encode(calced_verify_data) << "' Got";
            oss << "'" << util::base16_encode(finished.verify_data);
            FUNTLS_CHECK_FAILURE(oss.str());
        }
    }

private:
    boost::asio::ip::tcp::socket socket_;

    // State
    connection_end               connection_end_;
    protocol_version             current_protocol_version_ = protocol_version_tls_1_2;
    uint64_t                     encrypt_sequence_number_  = 0;
    uint64_t                     decrypt_sequence_number_  = 0;
    std::unique_ptr<cipher>      encrypt_cipher_           = make_cipher(null_cipher_parameters_e);
    std::unique_ptr<cipher>      decrypt_cipher_           = make_cipher(null_cipher_parameters_d);
    std::unique_ptr<cipher>      pending_encrypt_cipher_;
    std::unique_ptr<cipher>      pending_decrypt_cipher_;
    std::vector<uint8_t>         handshake_messages_;
    std::vector<uint8_t>         pending_handshake_messages_;

    void collapse_pending() {
        append_to_buffer(handshake_messages_, pending_handshake_messages_);
        pending_handshake_messages_.clear();
    }

    virtual std::vector<uint8_t> do_verify_data(tls::connection_end ce) const = 0;
};
} } // namespace funtls::tls

class tls_client : public tls::socket {
public:
    typedef std::function<void (const std::vector<x509::certificate>&)> verify_certificate_chain_func;

    explicit tls_client(boost::asio::ip::tcp::socket&& socket, const std::vector<tls::cipher_suite>& wanted_ciphers, const verify_certificate_chain_func& verify_certificate_chain)
        : tls::socket(tls::connection_end::client, std::move(socket))
        , wanted_ciphers_(wanted_ciphers)
        , verify_certificate_chain_(verify_certificate_chain)
        , client_random(tls::make_random()) {
        assert(!wanted_ciphers_.empty());
        assert(std::find(wanted_ciphers_.begin(), wanted_ciphers_.end(), tls::cipher_suite::null_with_null_null) == wanted_ciphers_.end());
        perform_handshake();
    }

private:
    std::vector<tls::cipher_suite>  wanted_ciphers_;
    tls::cipher_suite               negotiated_cipher_;
    verify_certificate_chain_func   verify_certificate_chain_;
    const tls::random               client_random;
    tls::random                     server_random;
    std::unique_ptr<client_key_exchange_protocol> client_kex;
    tls::session_id                 sesion_id;
    std::vector<uint8_t>            master_secret;

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
        send_change_cipher_spec();
        read_change_cipher_spec();

        std::cout << "Session " << util::base16_encode(sesion_id.as_vector()) << " in progress\n";
    }

    void send_client_hello() {
        std::vector<tls::extension> extensions;

        const bool use_ecc = std::any_of(
                begin(wanted_ciphers_),
                end(wanted_ciphers_),
                [](tls::cipher_suite cs) { return tls::is_ecc(tls::parameters_from_suite(cs).key_exchange_algorithm); }
                );

        static const std::vector<tls::signature_and_hash_algorithm> supported_signature_algorithms = {
            { tls::hash_algorithm::sha512 , tls::signature_algorithm::ecdsa },
            { tls::hash_algorithm::sha384 , tls::signature_algorithm::ecdsa },
            { tls::hash_algorithm::sha256 , tls::signature_algorithm::ecdsa },
            { tls::hash_algorithm::sha1   , tls::signature_algorithm::ecdsa },
            { tls::hash_algorithm::sha512 , tls::signature_algorithm::rsa   },
            { tls::hash_algorithm::sha384 , tls::signature_algorithm::rsa   },
            { tls::hash_algorithm::sha256 , tls::signature_algorithm::rsa   },
            { tls::hash_algorithm::sha1   , tls::signature_algorithm::rsa   },
        };
        extensions.push_back(tls::make_supported_signature_algorithms(supported_signature_algorithms));

        // Only send elliptic curve list if requesting at least one ECC cipher
        if (use_ecc) {
            static const tls::named_curve named_curves[] = {
                tls::named_curve::secp384r1,
                tls::named_curve::secp256r1,
            };
            // OpenSSL requires a list of supported named curves to support ECDH(E)_ECDSA
            extensions.push_back(tls::make_named_curves(named_curves));
            extensions.push_back(tls::make_ec_point_formats({tls::ec_point_format::uncompressed}));
        }

        std::cout << "Sending client hello." << std::endl;
        send_handshake(tls::make_handshake(
            tls::client_hello{
                current_protocol_version(),
                client_random,
                sesion_id,
                wanted_ciphers_,
                { tls::compression_method::null },
                extensions
            }
        ));
    }

    void read_server_hello() {
        std::cout << "Reading server hello." << std::endl;
        auto handshake = read_handshake();
        auto server_hello = tls::get_as<tls::server_hello>(handshake);
        negotiated_cipher_ = server_hello.cipher_suite;
        if (std::find(wanted_ciphers_.begin(), wanted_ciphers_.end(), negotiated_cipher_) == wanted_ciphers_.end()) {
            throw std::runtime_error("Invalid cipher suite returned " + util::base16_encode(&server_hello.cipher_suite, 2));
        }
        if (server_hello.compression_method != tls::compression_method::null) {
            throw std::runtime_error("Invalid compression method " + std::to_string((int)server_hello.compression_method));
        }
        for (const auto& e : server_hello.extensions) {
            if (e.type == tls::extension::ec_point_formats) {
                std::cerr << "Ignoring ec_point_formats extension in " << __FILE__ << ":" << __LINE__ << std::endl;
            } else {
                std::ostringstream msg;
                msg << "Unsupported TLS ServerHello extension " << e.type;
                FUNTLS_CHECK_FAILURE(msg.str());
            }
        }
        server_random = server_hello.random;
        sesion_id = server_hello.session_id;
        std::cout << "Negotiated cipher suite:\n" << tls::parameters_from_suite(negotiated_cipher_) << std::endl;
    }

    void read_until_server_hello_done() {
        const auto cipher_param = tls::parameters_from_suite(negotiated_cipher_);
        if (cipher_param.key_exchange_algorithm == tls::key_exchange_algorithm::rsa) {
            client_kex.reset(new rsa_client_kex_protocol{current_protocol_version()});
        } else if (cipher_param.key_exchange_algorithm == tls::key_exchange_algorithm::dhe_rsa) {
            client_kex.reset(new dhe_rsa_client_kex_protocol{client_random, server_random});
        } else if (cipher_param.key_exchange_algorithm == tls::key_exchange_algorithm::ecdhe_ecdsa) {
            client_kex.reset(new ecdhe_client_kex_protocol{tls::signature_algorithm::ecdsa, client_random, server_random});
        } else if (cipher_param.key_exchange_algorithm == tls::key_exchange_algorithm::ecdhe_rsa) {
            client_kex.reset(new ecdhe_client_kex_protocol{tls::signature_algorithm::rsa, client_random, server_random});
        } else {
            FUNTLS_CHECK_FAILURE("Internal error: Unsupported KeyExchangeAlgorithm " + std::to_string((int)(cipher_param.key_exchange_algorithm)));
        }

        std::vector<x509::certificate> certificate_list;

        // Note: Handshake messages are only allowed in a specific order

        auto handshake = read_handshake();
        if (handshake.type == tls::handshake_type::certificate) {
            std::cout << "Reading server certificate list." << std::endl;
            auto cert_message = tls::get_as<tls::certificate>(handshake);
            for (const auto& c : cert_message.certificate_list) {
                const auto v = c.as_vector();
                auto cert_buf = util::buffer_view{&v[0], v.size()};
                certificate_list.push_back(x509::certificate::parse(asn1::read_der_encoded_value(cert_buf)));
            }

            FUNTLS_CHECK_BINARY(certificate_list.size(), >, 0, "Empty certificate chain not allowed");
            verify_certificate_chain_(certificate_list);
            client_kex->certificate_list(certificate_list);

            handshake = read_handshake();
        }

        if (handshake.type == tls::handshake_type::server_key_exchange) {
            std::cout << "Reading server key exchange." << std::endl;
            client_kex->server_key_exchange(handshake);
            handshake = read_handshake();
        }

        // Only CertificateRequest allowed before ServerHelloDone
        std::cout << "Reading server hello done." << std::endl;

        (void) tls::get_as<tls::server_hello_done>(handshake);
    }

    void request_cipher_change(const std::vector<uint8_t>& pre_master_secret) {
        // We can now compute the master_secret as specified in rfc5246 8.1
        // master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]

        const auto cipher_param = tls::parameters_from_suite(negotiated_cipher_);
        std::vector<uint8_t> rand_buf;
        tls::append_to_buffer(rand_buf, client_random);
        tls::append_to_buffer(rand_buf, server_random);
        master_secret = tls::PRF(cipher_param.prf_algorithm, pre_master_secret, "master secret", rand_buf, tls::master_secret_size);
        assert(master_secret.size() == tls::master_secret_size);
        //std::cout << "Master secret: " << util::base16_encode(master_secret) << std::endl;

        // Now do Key Calculation http://tools.ietf.org/html/rfc5246#section-6.3
        // key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random)
        const size_t key_block_length  = 2 * cipher_param.mac_key_length + 2 * cipher_param.key_length + 2 * cipher_param.fixed_iv_length;
        auto key_block = tls::PRF(cipher_param.prf_algorithm, master_secret, "key expansion", tls::vec_concat(server_random.as_vector(), client_random.as_vector()), key_block_length);

        //std::cout << "Keyblock:\n" << util::base16_encode(key_block) << "\n";

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
        set_pending_ciphers(std::move(client_cipher_parameters), std::move(server_cipher_parameters));
    }

    void send_client_key_exchange() {
        std::vector<uint8_t> pre_master_secret;
        tls::handshake       client_key_exchange;
        assert(client_kex);
        std::tie(pre_master_secret, client_key_exchange) = client_kex->result();
        std::cout << "Sending client key exchange." << std::endl;
        send_handshake(client_key_exchange);
        request_cipher_change(pre_master_secret);
    }

    virtual std::vector<uint8_t> do_verify_data(tls::connection_end ce) const override {
        // verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1]
        // finished_label: 
        //      For Finished messages sent by the client, the string "client finished".
        //      For Finished messages sent by the server, the string "server finished".
        // handshake_messages:
        //      All of the data from all messages in this handshake (not
        //      including any HelloRequest messages) up to, but not including,
        //      this message
        const auto prf_algo       = tls::parameters_from_suite(negotiated_cipher_).prf_algorithm;
        const auto finished_label = ce == tls::connection_end::server ? "server finished" : "client finished";

        std::vector<uint8_t> handshake_digest;
        if (prf_algo == tls::prf_algorithm::sha256) {
            handshake_digest = hash::sha256{}.input(handshake_messages()).result();
        } else if (prf_algo == tls::prf_algorithm::sha384) {
             handshake_digest = hash::sha384{}.input(handshake_messages()).result();
        } else {
            std::ostringstream msg;
            msg << "Unsupported PRF algorithm " << prf_algo;
            FUNTLS_CHECK_FAILURE(msg.str());
        }
        return tls::PRF(prf_algo, master_secret, finished_label, handshake_digest, tls::finished::verify_data_min_length);
    }
};

class trust_store {
public:
    trust_store() {}

    void add(const x509::certificate& cert) {
        certs_.push_back(cert);
    }

    std::vector<const x509::certificate*> find(const x509::name& subject_name) const {
        std::vector<const x509::certificate*> res;
        for (const auto& cert : certs_) {
            if (cert.tbs().subject == subject_name) {
                try {
                    x509::verify_x509_signature(cert, cert);
                    res.push_back(&cert);
                } catch (const std::exception& e) {
                    std::cout << cert << "Not used: " << e.what() << std::endl;
                }
            }
        }
        return res;
    }

private:
    std::vector<x509::certificate> certs_;
};

#include <sys/types.h>
#include <dirent.h>
#include <string.h>

std::vector<std::string> all_files_in_dir(const std::string& dir)
{
    std::unique_ptr<DIR, decltype(&::closedir)> dir_(opendir(dir.c_str()), &::closedir);
    if (!dir_) {
        throw std::runtime_error("opendir('" + dir + "') failed: " + strerror(errno));
    }

    std::vector<std::string> files;
    while (dirent* de = readdir(dir_.get())) {
        if (de->d_name[0] == '.') {
            continue;
        }
        const auto p = dir + "/" + de->d_name;
        struct stat st;
        if (stat(p.c_str(), &st) < 0) {
            throw std::runtime_error("stat('" + p + "') failed: " + strerror(errno));
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        files.push_back(p);
    }
    return files;
}

void add_certificates_from_directory_to_trust_store(trust_store& ts, const std::string& path) {
    std::cout << "Adding certificates to trust store from " << path << std::endl;
    for (const auto& f : all_files_in_dir(path)) {
        assert(f.size() > path.size() + 1);
        const auto fn = f.substr(path.size()+1);
        std::cout << " " << fn << " ... " << std::flush;
        if (fn == "ca-certificates.crt") {
            std::cout << "HACK - skipping\n";
            continue;
        }
        auto cert = x509::read_pem_certificate_from_file(f);
        ts.add(cert);
        std::cout << cert.tbs().subject << std::endl;
    }
}

#include <fstream>

void add_all_certs_to_trust_store(trust_store& ts, const std::string& filename){
    std::ifstream in(filename, std::ifstream::binary);
    if (!in || !in.is_open()) throw std::runtime_error("Error opering " + filename);

    while (in && in.peek() != std::char_traits<char>::eof()) {
        auto cert = x509::read_pem_certificate(in);
        ts.add(cert);
    }

    if (!in) throw std::runtime_error("Error reading from " + filename);
}

void verify_cert_chain(const std::vector<x509::certificate>& certlist, const trust_store& ts)
{
    FUNTLS_CHECK_BINARY(certlist.size(), >, 0, "Empty certificate chain not allowed");
    const auto self_signed = certlist.back().tbs().subject == certlist.back().tbs().issuer;
    if (certlist.size() == 1 && self_signed) {
        std::cout << "Checking self-signed certificate\n" << certlist[0] << std::endl;
        x509::verify_x509_signature(certlist[0], certlist[0]);
        return;
    }
    auto complete_chain = certlist;
    if (!self_signed) {
        const auto root_issuer_name = certlist.back().tbs().issuer;
        // Incomplete chain, try to locate root certificate
        auto certs = ts.find(root_issuer_name);
        if (certs.empty()) {
            std::ostringstream oss;
            oss << "No valid certificate found in trust store for " << root_issuer_name;
            FUNTLS_CHECK_FAILURE(oss.str());
        }
        const x509::certificate* cert = nullptr;
        for (const auto& c : certs) {
            verify_x509_signature(*c, *c);
            if (!cert) {
                cert = c;
            } else {
                std::cout << "Warning multiple certificates could be used for " << c->tbs().subject << std::endl;
            }
        }
        if (!cert) {
            std::ostringstream oss;
            oss << "No valid certificate found in trust store for " << root_issuer_name;
            FUNTLS_CHECK_FAILURE(oss.str());
        }
        complete_chain.push_back(*cert);
    }
    std::cout << "Verifying trust chain:\n";
    for (const auto& cert : complete_chain) std::cout << cert << std::endl << std::endl;
    x509::verify_x509_certificate_chain(complete_chain);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " https-uri [cipher...]\n";
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

    std::vector<tls::cipher_suite> wanted_ciphers{
        tls::cipher_suite::ecdhe_ecdsa_with_aes_256_gcm_sha384,
        tls::cipher_suite::ecdhe_ecdsa_with_aes_128_gcm_sha256,
        tls::cipher_suite::ecdhe_rsa_with_aes_256_gcm_sha384,
        tls::cipher_suite::ecdhe_rsa_with_aes_128_gcm_sha256,
        tls::cipher_suite::rsa_with_aes_256_gcm_sha384,
        tls::cipher_suite::rsa_with_aes_128_gcm_sha256,
        tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha256,
        tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha256,
        tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha,
        tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha,
        tls::cipher_suite::rsa_with_aes_256_cbc_sha256,
        tls::cipher_suite::rsa_with_aes_128_cbc_sha256,
        tls::cipher_suite::rsa_with_aes_256_cbc_sha,
        tls::cipher_suite::rsa_with_aes_128_cbc_sha,
        tls::cipher_suite::dhe_rsa_with_3des_ede_cbc_sha,
        tls::cipher_suite::rsa_with_3des_ede_cbc_sha,
        tls::cipher_suite::rsa_with_rc4_128_sha,
        tls::cipher_suite::rsa_with_rc4_128_md5,
    };
    if (argc > 2) {
        wanted_ciphers.clear();
        for (int arg = 2; arg < argc; ++arg) {
            std::string wanted_cipher_txt = argv[arg];
            tls::cipher_suite wanted_cipher = tls::cipher_suite::null_with_null_null;
            FUNTLS_CHECK_BINARY(bool(std::istringstream(wanted_cipher_txt)>>wanted_cipher), !=, false, "Invalid cipher " + wanted_cipher_txt);
            FUNTLS_CHECK_BINARY(wanted_cipher, !=, tls::cipher_suite::null_with_null_null, "Invalid cipher " + wanted_cipher_txt);
            wanted_ciphers.push_back(wanted_cipher);
        }
    }
    FUNTLS_CHECK_BINARY(wanted_ciphers.size(), !=, 0, "No ciphers");

    trust_store ts;
    //add_certificates_from_directory_to_trust_store(ts, "/etc/ssl/certs");
    add_all_certs_to_trust_store(ts, "/etc/ssl/certs/ca-certificates.crt");

    boost::asio::io_service         io_service;
    boost::asio::ip::tcp::socket    socket(io_service);
    boost::asio::ip::tcp::resolver  resolver(io_service);

    std::cout << "Connecting to " << host << ":" << port << " ..." << std::flush;
    boost::asio::connect(socket, resolver.resolve({host, port}));
    std::cout << " OK" << std::endl;
    tls_client::verify_certificate_chain_func cf = std::bind(&verify_cert_chain, std::placeholders::_1, ts);
    tls_client client{std::move(socket), wanted_ciphers, cf};

    const auto data = "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n";
    client.send_app_data(std::vector<uint8_t>(data.begin(), data.end()));

    // Ugly!
    bool got_app_data = false;
    for (;;) {
        try {
            const auto res = client.next_app_data();
            std::cout << std::string(res.begin(), res.end()) << std::endl;
            got_app_data = true;
        } catch (const std::exception& e) {
            if (!got_app_data) throw;
            std::cout << e.what() << std::endl;
            break;
        }
    }

    return 0;
}
