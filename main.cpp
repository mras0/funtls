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
#include <util/async_result.h>
#include <int_util/int_util.h>
#include <tls/tls.h>
#include <tls/tls_ecc.h>
#include <tls/tls_kex.h>

using namespace funtls;

namespace {

std::exception_ptr make_exception(boost::system::error_code ec)
{
    return std::make_exception_ptr(boost::system::system_error(ec));
}

namespace detail {
template<typename T>
struct arg_type;

template<typename T>
struct arg_type : public arg_type<decltype(&T::operator())> {
};

template<typename C, typename R>
struct arg_type<R (C::*)() const> {
    using type = void;
};

template<typename C, typename R, typename A>
struct arg_type<R (C::*)(A&&) const> {
    using type = A;
};
} // namespace detail

template<typename F, typename T>
void do_wrapped(F f, const std::function<void (util::async_result<T>)>& handler) {
    try {
        f();
    } catch (...) {
        handler(std::current_exception());
    }
}

template<typename F, typename T1 = typename detail::arg_type<F>::type, typename T2>
typename std::enable_if<!std::is_same<T1, void>::value, std::function<void (util::async_result<T1>)>>::type wrapped(F f, const std::function<void (util::async_result<T2>)>& handler)
{
    return [=] (util::async_result<T1> res) {
        try {
            f(res.get());
        } catch (...) {
            handler(std::current_exception());
        }
    };
}

template<typename F, typename T1 = typename detail::arg_type<F>::type, typename T2>
typename std::enable_if<std::is_same<T1, void>::value, std::function<void (util::async_result<T1>)>>::type wrapped(F f, const std::function<void (util::async_result<T2>)>& handler)
{
    return [=] (util::async_result<T1> res) {
        try {
            res.get();
            f();
        } catch (...) {
            handler(std::current_exception());
        }
    };
}

} // unnamed namespace

namespace funtls { namespace tls {

enum class connection_end { server, client };

// TODO: Handle record fragmentation/coalescence
class socket {
public:
    using app_data_sent_handler = std::function<void (util::async_result<void>)>;
    using app_data_handler = std::function<void (util::async_result<std::vector<uint8_t>>)>;

    void send_app_data(const std::vector<uint8_t>& d, const app_data_sent_handler& handler) {
        send_record(content_type::application_data, d, handler);
    }

    void next_app_data(const app_data_handler& handler) {
        recv_record(wrapped(
            [handler] (record&& record) {
                FUNTLS_CHECK_BINARY(record.type, ==, content_type::application_data, "Unexpected content type");
                handler(std::move(record.fragment));
            }, handler));
    }

protected:
    explicit socket(connection_end ce, boost::asio::ip::tcp::socket&& socket)
        : socket_(std::move(socket))
        , connection_end_(ce) {
    }

    using done_handler           = std::function<void(util::async_result<void>)>;
    using recv_record_handler    = std::function<void(util::async_result<record>)>;
    using recv_handshake_handler = std::function<void(util::async_result<handshake>)>;

    void send_record(tls::content_type content_type, const std::vector<uint8_t>& plaintext, const done_handler& handler) {
        do_wrapped([&] {
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

            send_buffer_.clear();
            append_to_buffer(send_buffer_, content_type);
            append_to_buffer(send_buffer_, current_protocol_version_);
            append_to_buffer(send_buffer_, uint16(fragment.size()));
            assert(send_buffer_.size() == 5);
            append_to_buffer(send_buffer_, fragment);
        }, handler);

        boost::asio::async_write(socket_, boost::asio::buffer(send_buffer_),
                [this, handler](const boost::system::error_code& ec, size_t) {
                    if (ec) {
                        handler(make_exception(ec));
                        return;
                    }
                    handler(util::async_result<void>{});
                });
    }

    void recv_record(const recv_record_handler& handler) {
        do_wrapped([&] {
            collapse_pending();
            recv_buffer_.resize(5);
        }, handler);
        boost::asio::async_read(socket_, boost::asio::buffer(recv_buffer_),
                [this, handler](const boost::system::error_code& ec, size_t) {
                    if (ec) {
                        handler(make_exception(ec));
                        return;
                    }
                    do_recv_record_content(handler);
                });
    }

    void send_handshake(const handshake& handshake, const done_handler& handler) {
        do_wrapped([&] {
            assert(handshake.content_type == content_type::handshake);
            std::vector<uint8_t> payload_buffer;
            append_to_buffer(payload_buffer, handshake);
            send_record(handshake.content_type, payload_buffer, handler);
        }, handler);
    }

    void read_handshake(const recv_handshake_handler& handler) {
        recv_record(wrapped([this, handler](record&& record) {
                FUNTLS_CHECK_BINARY(record.type, ==, content_type::handshake, "Invalid content type");

                util::buffer_view frag_buf{&record.fragment[0], record.fragment.size()};
                handshake handshake;
                from_bytes(handshake, frag_buf);
                if (frag_buf.remaining()) {
                    FUNTLS_CHECK_FAILURE("Unread handshake data. Fragment: " + util::base16_encode(record.fragment));
                }
                handler(std::move(handshake));
            }, handler));
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

    void send_change_cipher_spec(const done_handler& handler) {
        do_wrapped([&] {
            std::cout << "Sending change cipher spec." << std::endl;
            if (!pending_encrypt_cipher_) {
                FUNTLS_CHECK_FAILURE("Sending ChangeCipherSpec without a pending cipher suite");
            }
            change_cipher_spec msg{};
            std::vector<uint8_t> payload_buffer;
            append_to_buffer(payload_buffer, msg);
            //
            // Immediately after sending [the ChangeCipherSpec] message, the sender MUST instruct the
            // record layer to make the write pending state the write active state.
            //
            send_record(msg.content_type, payload_buffer, wrapped([this, handler] () {
                    send_finished(handler);
                }, handler));
        }, handler);
    }

    void read_change_cipher_spec(const done_handler& handler) {
        recv_record(wrapped([this, handler] (record&& record) {
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

                do_read_finished(handler);
            }, handler));
    }

    void do_read_finished(const done_handler& handler) {
        // Read finished
        read_handshake(wrapped([this, handler] (handshake&& handshake) {
                auto finished = tls::get_as<tls::finished>(handshake);
                const auto calced_verify_data = do_verify_data(connection_end_ == connection_end::server ? connection_end::client : connection_end::server);
                if (finished.verify_data != calced_verify_data) {
                    std::ostringstream oss;
                    oss << "Got invalid finished message. verify_data check failed. Expected ";
                    oss << "'" << util::base16_encode(calced_verify_data) << "' Got";
                    oss << "'" << util::base16_encode(finished.verify_data);
                    FUNTLS_CHECK_FAILURE(oss.str());
                }
                handler(util::async_result<void>{});
            }, handler));
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

    std::vector<uint8_t>         send_buffer_;
    std::vector<uint8_t>         recv_buffer_;

    void collapse_pending() {
        append_to_buffer(handshake_messages_, pending_handshake_messages_);
        pending_handshake_messages_.clear();
    }

    void do_recv_record_content(const recv_record_handler& handler) {
        do_wrapped([&] {
            util::buffer_view     buf_view{&recv_buffer_[0], recv_buffer_.size()};
            content_type          content_type;
            protocol_version      protocol_version;
            uint16                length;
            from_bytes(content_type, buf_view);
            from_bytes(protocol_version, buf_view);
            from_bytes(length, buf_view);
            assert(buf_view.remaining() == 0);

            FUNTLS_CHECK_BINARY(protocol_version, ==, current_protocol_version(), "Wrong TLS version");
            FUNTLS_CHECK_BINARY(length, >=, 1, "Illegal fragment size");
            FUNTLS_CHECK_BINARY(length, <=, record::max_ciphertext_length, "Illegal fragment size");

            recv_buffer_.resize(length);
            assert(recv_buffer_.size() <= record::max_ciphertext_length);
            boost::asio::async_read(socket_, boost::asio::buffer(recv_buffer_),
                    [this, content_type, protocol_version, handler](const boost::system::error_code& ec, size_t) {
                        if (ec) {
                            handler(make_exception(ec));
                            return;
                        }
                        do_decrypt(content_type, protocol_version, handler);
                    });
        }, handler);
    }

    void do_decrypt(tls::content_type content_type, tls::protocol_version protocol_version, const recv_record_handler& handler) {
        do_wrapped([&] {
            //
            // Decrypt
            //
            const auto ver_buffer = verification_buffer(decrypt_sequence_number_++, content_type, current_protocol_version(), 0 /* filled in later */);
            recv_buffer_ = decrypt_cipher_->process(recv_buffer_, ver_buffer);

            // Decompression would happen here
            FUNTLS_CHECK_BINARY(recv_buffer_.size(), <=, record::max_compressed_length, "Illegal decoded fragment size");

            //
            // We now have a TLSPlaintext buffer for consumption
            //
            FUNTLS_CHECK_BINARY(recv_buffer_.size(), <=, record::max_plaintext_length, "Illegal decoded fragment size");

            if (content_type == tls::content_type::alert) {
                util::buffer_view alert_buf(&recv_buffer_[0], recv_buffer_.size());
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
                pending_handshake_messages_ = recv_buffer_; // Will not become actove after this message has been parsed. This is a HACK
            }

            handler(record{content_type, protocol_version, std::move(recv_buffer_)});
        }, handler);
    }

    void send_finished(const done_handler& handler) {
        assert(encrypt_cipher_);
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
        send_handshake(tls::make_handshake(tls::finished{do_verify_data(connection_end_)}), handler);
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
    }

    void perform_handshake(const done_handler& handler) {
        do_wrapped([this, handler] { send_client_hello(handler); }, handler);
    }

private:
    std::vector<tls::cipher_suite>  wanted_ciphers_;
    tls::cipher_suite               negotiated_cipher_;
    verify_certificate_chain_func   verify_certificate_chain_;
    const tls::random               client_random;
    tls::random                     server_random;
    std::unique_ptr<tls::client_key_exchange_protocol> client_kex;
    tls::session_id                 sesion_id;
    std::vector<uint8_t>            master_secret;

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

    void send_client_hello(const done_handler& handler) {
        std::cout << "Sending client hello\n";
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
            }), wrapped([this, handler] () {
                read_server_hello(handler);
            }, handler));
    }

    void read_server_hello(const done_handler& handler) {
        std::cout << "Reading server hello." << std::endl;
        read_handshake(wrapped([this, handler] (tls::handshake&& handshake) {
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

                const auto cipher_param = tls::parameters_from_suite(negotiated_cipher_);
                client_kex = tls::make_client_key_exchange_protocol(cipher_param.key_exchange_algorithm, current_protocol_version(), client_random, server_random);

                std::cout << "Reading until server hello done\n";
                // Note: Handshake messages are only allowed in a specific order
                read_next_server_handshake({
                        tls::handshake_type::certificate,
                        tls::handshake_type::server_key_exchange,
                        tls::handshake_type::server_hello_done,
                        }, handler);
            }, handler));
    }

    void read_next_server_handshake(const std::vector<tls::handshake_type>& allowed_handshakes, const done_handler& handler) {
        assert(!allowed_handshakes.empty());
        read_handshake(wrapped([this, allowed_handshakes, handler] (tls::handshake&& handshake) {
                auto ah = allowed_handshakes;
                while (!ah.empty() && ah.front() != handshake.type) {
                    ah.erase(ah.begin());
                }
                if (ah.empty()) {
                    std::ostringstream oss;
                    oss << "Got unexpected handshake " << int(handshake.type);
                    FUNTLS_CHECK_FAILURE(oss.str());
                }

                if (handshake.type == tls::handshake_type::server_hello_done) {
                    std::cout << "Reading server hello done." << std::endl;

                    (void) tls::get_as<tls::server_hello_done>(handshake);
                    send_client_key_exchange(handler);
                    return;
                }

                if (handshake.type == tls::handshake_type::certificate) {
                    std::cout << "Reading server certificate list." << std::endl;
                    auto cert_message = tls::get_as<tls::certificate>(handshake);
                    std::vector<x509::certificate> certificate_list;
                    for (const auto& c : cert_message.certificate_list) {
                        const auto v = c.as_vector();
                        auto cert_buf = util::buffer_view{&v[0], v.size()};
                        certificate_list.push_back(x509::certificate::parse(asn1::read_der_encoded_value(cert_buf)));
                    }

                    FUNTLS_CHECK_BINARY(certificate_list.size(), >, 0, "Empty certificate chain not allowed");
                    verify_certificate_chain_(certificate_list);
                    client_kex->certificate_list(certificate_list);
                } else if (handshake.type == tls::handshake_type::server_key_exchange) {
                    std::cout << "Reading server key exchange." << std::endl;
                    client_kex->server_key_exchange(handshake);
                } else {
                    // Only CertificateRequest allowed before ServerHelloDone
                    std::ostringstream oss;
                    oss << "Got unexpected handshake " << int(handshake.type);
                    FUNTLS_CHECK_FAILURE(oss.str());
                }

                read_next_server_handshake(ah, handler);
            }, handler));
    }

    void request_cipher_change(const std::vector<uint8_t>& pre_master_secret, const done_handler& handler) {
        do_wrapped([&] {
            std::cout << "Requesting cipher change\n";
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

            send_change_cipher_spec(wrapped([this, handler] () {
                        std::cout << "Reading change cipher spec\n";
                        read_change_cipher_spec(wrapped([this, handler] () {
                                    std::cout << "Handshake done. Session id " << util::base16_encode(sesion_id.as_vector()) << std::endl;
                                    handler(util::async_result<void>{});
                                }, handler));
                    }, handler));
        }, handler);
    }

    void send_client_key_exchange(const done_handler& handler) {
        do_wrapped([&] {
            std::cout << "Sending client key exchange\n";
            std::vector<uint8_t> pre_master_secret;
            tls::handshake       client_key_exchange;
            assert(client_kex);
            std::tie(pre_master_secret, client_key_exchange) = client_kex->result();
            std::cout << "Sending client key exchange." << std::endl;
            send_handshake(client_key_exchange,
                    wrapped([this, pre_master_secret, handler] () {
                        request_cipher_change(pre_master_secret, handler);
                    }, handler));
        }, handler);
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

    tls::socket::app_data_handler got_app_data = [&] (util::async_result<std::vector<uint8_t>> res) {
        try {
            auto data = res.get();
            std::cout << std::string(data.begin(), data.end()) << std::flush;
            client.next_app_data(got_app_data);
        } catch (const boost::system::system_error& e) {
            if (e.code() == boost::asio::error::eof) {
                std::cout << "Got EOF\n";
                io_service.stop();
                return;
            }
            throw;
        }
    };

    client.perform_handshake([&] (util::async_result<void> res) {
            res.get();
            std::cout << "Handshake done!\n";
            const auto data = "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n";
            client.send_app_data(std::vector<uint8_t>(data.begin(), data.end()), [&] (util::async_result<void> res) {
                    res.get();
                    client.next_app_data(got_app_data);
                });
        });
    io_service.run();
    std::cout << "io service exiting\n";

    return 0;
}
