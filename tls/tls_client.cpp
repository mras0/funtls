#include <tls/tls_client.h>
#include <tls/tls_kex.h>
#include <tls/tls_ser.h>
#include <util/test.h>
#include <util/base_conversion.h>
#include <assert.h>
#include <algorithm>

#include <iostream>

#include <tls/tls_ecc.h>

using namespace funtls;
using util::wrapped;
using util::do_wrapped;

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

namespace funtls { namespace tls {

client::client(std::unique_ptr<stream> stream, const std::vector<cipher_suite>& wanted_ciphers, const verify_certificate_chain_func& verify_certificate_chain)
    : tls_base(std::move(stream), tls_base::connection_end::client)
    , wanted_ciphers_(wanted_ciphers)
    , verify_certificate_chain_(verify_certificate_chain)
{
    assert(!wanted_ciphers_.empty());
    assert(std::find(wanted_ciphers_.begin(), wanted_ciphers_.end(), cipher_suite::null_with_null_null) == wanted_ciphers_.end());
    current_protocol_version(protocol_version_tls_1_2);
}

client::~client() = default;

void client::perform_handshake(const done_handler& handler) {
    do_wrapped([this, handler] { send_client_hello(handler); }, handler);
}

void client::send_client_hello(const done_handler& handler) {
    std::cout << "Sending client hello\n";
    std::vector<extension> extensions;

    const bool use_ecc = std::any_of(
            begin(wanted_ciphers_),
            end(wanted_ciphers_),
            [](cipher_suite cs) { return is_ecc(parameters_from_suite(cs).key_exchange_algorithm); }
            );

    static const std::vector<signature_and_hash_algorithm> supported_signature_algorithms = {
        { hash_algorithm::sha512 , signature_algorithm::ecdsa },
        { hash_algorithm::sha384 , signature_algorithm::ecdsa },
        { hash_algorithm::sha256 , signature_algorithm::ecdsa },
        { hash_algorithm::sha1   , signature_algorithm::ecdsa },
        { hash_algorithm::sha512 , signature_algorithm::rsa   },
        { hash_algorithm::sha384 , signature_algorithm::rsa   },
        { hash_algorithm::sha256 , signature_algorithm::rsa   },
        { hash_algorithm::sha1   , signature_algorithm::rsa   },
    };
    extensions.push_back(make_supported_signature_algorithms(supported_signature_algorithms));

    // Only send elliptic curve list if requesting at least one ECC cipher
    if (use_ecc) {
        static const named_curve named_curves[] = {
            named_curve::secp384r1,
            named_curve::secp256r1,
        };
        // OpenSSL requires a list of supported named curves to support ECDH(E)_ECDSA
        extensions.push_back(make_named_curves(named_curves));
        extensions.push_back(make_ec_point_formats({ec_point_format::uncompressed}));
    }

    std::cout << "Sending client hello." << std::endl;
    send_handshake(make_handshake(
        client_hello{
            current_protocol_version(),
            client_random(),
            session_id(),
            wanted_ciphers_,
            { compression_method::null },
            extensions
        }), wrapped([this, handler] () {
            read_server_hello(handler);
        }, handler));
}

void client::read_server_hello(const done_handler& handler)
{
    std::cout << "Reading server hello." << std::endl;
    read_handshake(wrapped([this, handler] (handshake&& handshake) {
            auto server_hello = get_as<tls::server_hello>(handshake);
            if (std::find(wanted_ciphers_.begin(), wanted_ciphers_.end(), server_hello.cipher_suite) == wanted_ciphers_.end()) {
                throw std::runtime_error("Invalid cipher suite returned " + util::base16_encode(&server_hello.cipher_suite, 2));
            }
            if (server_hello.compression_method != compression_method::null) {
                throw std::runtime_error("Invalid compression method " + std::to_string((int)server_hello.compression_method));
            }
            for (const auto& e : server_hello.extensions) {
                if (e.type == extension::ec_point_formats) {
                    std::cerr << "Ignoring ec_point_formats extension in " << __FILE__ << ":" << __LINE__ << std::endl;
                } else {
                    std::ostringstream msg;
                    msg << "Unsupported TLS ServerHello extension " << e.type;
                    FUNTLS_CHECK_FAILURE(msg.str());
                }
            }
            negotiated_cipher(server_hello.cipher_suite);
            server_random(server_hello.random);
            session_id(server_hello.session_id);
            std::cout << "Negotiated cipher suite:\n" << current_cipher_parameters() << std::endl;

            client_kex = make_client_key_exchange_protocol(current_cipher_parameters().key_exchange_algorithm, current_protocol_version(), client_random(), server_random());

            std::cout << "Reading until server hello done\n";
            // Note: Handshake messages are only allowed in a specific order
            read_next_server_handshake({
                    handshake_type::certificate,
                    handshake_type::server_key_exchange,
                    handshake_type::server_hello_done,
                    }, handler);
        }, handler));
}

void client::read_next_server_handshake(const std::vector<handshake_type>& allowed_handshakes, const done_handler& handler)
{
    assert(!allowed_handshakes.empty());
    read_handshake(wrapped([this, allowed_handshakes, handler] (handshake&& handshake) {
            auto ah = allowed_handshakes;
            while (!ah.empty() && ah.front() != handshake.type) {
                ah.erase(ah.begin());
            }
            if (ah.empty()) {
                std::ostringstream oss;
                oss << "Got unexpected handshake " << int(handshake.type);
                FUNTLS_CHECK_FAILURE(oss.str());
            }

            if (handshake.type == handshake_type::server_hello_done) {
                std::cout << "Reading server hello done." << std::endl;

                (void) get_as<server_hello_done>(handshake);
                send_client_key_exchange(handler);
                return;
            }

            if (handshake.type == handshake_type::certificate) {
                std::cout << "Reading server certificate list." << std::endl;
                auto cert_message = get_as<certificate>(handshake);
                std::vector<x509::certificate> certificate_list;
                for (const auto& c : cert_message.certificate_list) {
                    const auto v = c.as_vector();
                    auto cert_buf = util::buffer_view{&v[0], v.size()};
                    certificate_list.push_back(x509::certificate::parse(asn1::read_der_encoded_value(cert_buf)));
                }

                FUNTLS_CHECK_BINARY(certificate_list.size(), >, 0, "Empty certificate chain not allowed");
                verify_certificate_chain_(certificate_list);
                client_kex->certificate_list(certificate_list);
            } else if (handshake.type == handshake_type::server_key_exchange) {
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

void client::request_cipher_change(const std::vector<uint8_t>& pre_master_secret, const done_handler& handler)
{
    do_wrapped([&] {
        std::cout << "Requesting cipher change\n";
        // We can now compute the master_secret as specified in rfc5246 8.1
        // master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]

        const auto cipher_param = current_cipher_parameters();
        std::vector<uint8_t> rand_buf;
        append_to_buffer(rand_buf, client_random());
        append_to_buffer(rand_buf, server_random());
        master_secret(PRF(cipher_param.prf_algorithm, pre_master_secret, "master secret", rand_buf, master_secret_size));
        //std::cout << "Master secret: " << util::base16_encode(master_secret) << std::endl;

        // Now do Key Calculation http://tools.ietf.org/html/rfc5246#section-6.3
        // key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random)
        const size_t key_block_length  = 2 * cipher_param.mac_key_length + 2 * cipher_param.key_length + 2 * cipher_param.fixed_iv_length;
        std::vector<uint8_t> randbuf;
        append_to_buffer(randbuf, server_random());
        append_to_buffer(randbuf, client_random());
        auto key_block = PRF(cipher_param.prf_algorithm, master_secret(), "key expansion", randbuf, key_block_length);

        //std::cout << "Keyblock:\n" << util::base16_encode(key_block) << "\n";

        size_t i = 0;
        auto client_mac_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.mac_key_length]};  i += cipher_param.mac_key_length;
        auto server_mac_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.mac_key_length]};  i += cipher_param.mac_key_length;
        auto client_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.key_length]};      i += cipher_param.key_length;
        auto server_enc_key = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.key_length]};      i += cipher_param.key_length;
        auto client_iv      = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.fixed_iv_length]}; i += cipher_param.fixed_iv_length;
        auto server_iv      = std::vector<uint8_t>{&key_block[i], &key_block[i+cipher_param.fixed_iv_length]}; i += cipher_param.fixed_iv_length;
        assert(i == key_block.size());

        cipher_parameters client_cipher_parameters{cipher_parameters::encrypt, cipher_param, client_mac_key, client_enc_key, client_iv};
        cipher_parameters server_cipher_parameters{cipher_parameters::decrypt, cipher_param, server_mac_key, server_enc_key, server_iv};

        // TODO: This should obviously be reversed if running as a server
        set_pending_ciphers(std::move(client_cipher_parameters), std::move(server_cipher_parameters));

        send_change_cipher_spec(wrapped([this, handler] () {
                    std::cout << "Reading change cipher spec\n";
                    read_change_cipher_spec(wrapped([this, handler] () {
                                std::cout << "Handshake done. Session id " << util::base16_encode(session_id().as_vector()) << std::endl;
                                handler(util::async_result<void>{});
                            }, handler));
                }, handler));
    }, handler);
}

void client::send_client_key_exchange(const done_handler& handler)
{
    do_wrapped([&] {
        std::cout << "Sending client key exchange\n";
        std::vector<uint8_t> pre_master_secret;
        handshake       client_key_exchange;
        assert(client_kex);
        std::tie(pre_master_secret, client_key_exchange) = client_kex->result();
        std::cout << "Sending client key exchange." << std::endl;
        send_handshake(client_key_exchange,
                wrapped([this, pre_master_secret, handler] () {
                    request_cipher_change(pre_master_secret, handler);
                }, handler));
    }, handler);
}

std::vector<uint8_t> client::do_verify_data(tls_base::connection_end ce) const
{
    // verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1]
    // finished_label: 
    //      For Finished messages sent by the client, the string "client finished".
    //      For Finished messages sent by the server, the string "server finished".
    // handshake_messages:
    //      All of the data from all messages in this handshake (not
    //      including any HelloRequest messages) up to, but not including,
    //      this message
    const auto prf_algo       = current_cipher_parameters().prf_algorithm;
    const auto finished_label = ce == tls_base::connection_end::server ? "server finished" : "client finished";

    std::vector<uint8_t> handshake_digest;
    if (prf_algo == prf_algorithm::sha256) {
        handshake_digest = hash::sha256{}.input(handshake_messages()).result();
    } else if (prf_algo == prf_algorithm::sha384) {
         handshake_digest = hash::sha384{}.input(handshake_messages()).result();
    } else {
        std::ostringstream msg;
        msg << "Unsupported PRF algorithm " << prf_algo;
        FUNTLS_CHECK_FAILURE(msg.str());
    }
    return PRF(prf_algo, master_secret(), finished_label, handshake_digest, finished::verify_data_min_length);
}

} } // namespace funtls::tls
