#include <iostream>

#include <util/test.h>
#include <util/base_conversion.h>
#include <x509/x509_rsa.h>
#include <x509/x509_ec.h>
#include <tls/tls_base.h>
#include <tls/tls_ser.h>
#include <tls/tls_ecc.h>
#include <int_util/int.h>
#include <int_util/int_util.h>
#include <asio_stream_adapter.h>
#include <util/ostream_adapter.h>

using namespace funtls;
using util::async_result;
using util::wrapped;
using util::do_wrapped;

namespace funtls { namespace tls {

class server_key_exchange_protocol {
public:
    virtual ~server_key_exchange_protocol() {}

    // returns nullptr if no ServerCertificate message should be sent, a list of certificates to send otherwise
    const std::vector<asn1cert>* certificate_chain() const {
        return do_certificate_chain();
    }

    // returns nullptr if no ServerKexEchange message should be sent, the appropriate handshake otherwise
    std::unique_ptr<handshake> server_key_exchange(const random& client_random, const random& server_random) const {
        return do_server_key_exchange(client_random, server_random);
    }

    // returns the master secret, the handshake is the ClientKeyExchange message received from the client
    std::vector<uint8_t> client_key_exchange(const handshake& handshake) const {
        return do_client_key_exchange(handshake);
    }

private:
    virtual const std::vector<asn1cert>* do_certificate_chain() const = 0;
    virtual std::unique_ptr<handshake> do_server_key_exchange(const random& client_random, const random& server_random) const = 0;
    virtual std::vector<uint8_t> do_client_key_exchange(const handshake&) const = 0;
};

class server_id {
public:
    virtual bool supports(key_exchange_algorithm) const = 0;
    virtual std::unique_ptr<server_key_exchange_protocol> key_exchange_protocol(key_exchange_algorithm) const = 0;
};

class connection : private tls_base, public std::enable_shared_from_this<connection> {
public:
    using ptr_t = std::shared_ptr<connection>;

    static ptr_t make(const std::string& name, std::unique_ptr<stream> stream, const std::vector<const server_id*> server_ids) {
        auto c = ptr_t(new connection{name, std::move(stream), server_ids});
        c->read_client_hello();
        return c;
    }

    ~connection();
private:
    util::ostream_adapter                           log_;
    std::vector<const server_id*>                   server_ids_;
    std::unique_ptr<server_key_exchange_protocol>   server_kex_;

    connection(const std::string& name, std::unique_ptr<stream> stream, const std::vector<const server_id*> server_ids);

    void read_client_hello();
    void send_server_hello();
    void send_server_certificate();
    void send_server_key_exchange();
    void send_server_hello_done();
    void read_client_key_exchange();
    void main_loop();

    void handle_error(std::exception_ptr e) const;
};

connection::connection(const std::string& name, std::unique_ptr<stream> stream, const std::vector<const server_id*> server_ids)
    : tls_base(std::move(stream), tls_base::connection_end::server)
    , log_([name] (const std::string& s) { std::cout << name + ": " + s;} )
    , server_ids_(server_ids)
    , server_kex_(nullptr)
{
    log_ << "Connected" << std::endl;
    assert(!server_ids_.empty());
}

connection::~connection()
{
    log_ << "Conncetion dropped" << std::endl;
}

void connection::handle_error(std::exception_ptr e) const
{
    assert(e);
    std::ostringstream msg;
    msg << "[!!!] ";
    try {
        std::rethrow_exception(e);
    } catch (const std::exception& e) {
        msg << e.what();
    } catch (...) {
        msg << "Unknown exception type caught";
    }
    msg << "" << std::endl;
    const_cast<util::ostream_adapter&>(log_) << msg.str(); // Meh...
}


void connection::read_client_hello() {
    log_ << "Reading ClientHello" << std::endl;
    auto self = shared_from_this();
    read_handshake(wrapped(
            [self] (tls::handshake&& handshake) {
                auto client_hello = get_as<tls::client_hello>(handshake);
                self->log_ << "Got client hello" << std::endl;
                self->log_ << "version " << client_hello.client_version << "" << std::endl;
                self->log_ << "session " << util::base16_encode(client_hello.session_id.as_vector()) << "" << std::endl;
                self->log_ << "cipher_suites:";
                for (auto cs : client_hello.cipher_suites.as_vector()) {
                    self->log_ << " " << cs;
                }
                self->log_ << "" << std::endl;
                self->log_ << "compression_methods:";
                for (auto cm : client_hello.compression_methods.as_vector()) {
                    self->log_ << " " << (int)cm;
                }
                self->log_ << "" << std::endl;
                self->log_ << "extensions:" << std::endl;
                for (const auto& ext : client_hello.extensions) {
                    self->log_ << " ";
                    switch (ext.type) {
                    case extension_type::server_name:
                        {
                            auto sne = get_as<server_name_extension>(ext);
                            FUNTLS_CHECK_BINARY(sne.server_name_list.size(), ==, 1, "Invalid server name extension");
                            FUNTLS_CHECK_BINARY(int(sne.server_name_list[0].name_type), ==, int(server_name::server_name_type::host_name), "Invalid server name extension");
                            self->log_ << sne;
                        }
                        break;
                    case extension_type::elliptic_curves:
                        self->log_ << get_as<elliptic_curves_extension>(ext);
                        break;
                    case extension_type::ec_point_formats:
                        self->log_ << get_as<ec_point_formats_extension>(ext);
                        break;
                    case extension_type::signature_algorithms:
                        self->log_ << get_as<signature_algorithms_extension>(ext);
                        break;
                    case extension_type::application_layer_protocol_negotiation:
                        self->log_ << get_as<application_layer_protocol_negotiation_extension>(ext);
                        break;
                    default:
                        self->log_ << ext.type << " " << util::base16_encode(ext.data.as_vector());
                    }
                    self->log_ << std::endl;
                }

                auto cipher = cipher_suite::null_with_null_null;
                // Find the first supported cipher
                for (auto cs : client_hello.cipher_suites.as_vector()) {
                    if (is_supported(cs)) {
                        const auto kex = parameters_from_suite(cs).key_exchange_algorithm;
                        for (auto id : self->server_ids_) {
                            if (id->supports(kex)) {
                                assert(self->server_kex_ == nullptr);
                                cipher            = cs;
                                self->server_kex_ = id->key_exchange_protocol(kex);
                                break;
                            }
                        }
                    }
                    if (cipher != cipher_suite::null_with_null_null) {
                        break;
                    }
                }
                FUNTLS_CHECK_BINARY(client_hello.client_version, >=, tls::protocol_version_tls_1_2, "Invalid protocol version");
                FUNTLS_CHECK_BINARY(cipher, !=, cipher_suite::null_with_null_null, "No common cipher found");
                self->current_protocol_version(tls::protocol_version_tls_1_2);
                self->client_random(client_hello.random);
                self->negotiated_cipher(cipher);
                // TODO: Check that "No compression" is supported
                self->log_ << "Negotatiated cipher: " << cipher << std::endl;
                assert(self->server_kex_);

                self->send_server_hello();
            },
            std::bind(&connection::handle_error, self, std::placeholders::_1)));
}

void connection::send_server_hello()
{
    log_ << "Sending ServerHello" << std::endl;
    auto self = shared_from_this();
    send_handshake(make_handshake(
        server_hello{
            current_protocol_version(),
            server_random(),
            session_id(),
            negotiated_cipher(),
            compression_method::null,
            std::vector<extension>{}
        }), wrapped([self] () {
            self->send_server_certificate();
        }, std::bind(&connection::handle_error, self, std::placeholders::_1)));
}

void connection::send_server_certificate()
{
    const auto chain = server_kex_->certificate_chain();
    if (chain) {
        log_ << "Sending ServerCertificate" << std::endl;
        auto self = shared_from_this();
        send_handshake(make_handshake(
            certificate{ *chain }), wrapped([self] () {
                self->send_server_key_exchange();
            }, std::bind(&connection::handle_error, self, std::placeholders::_1)));
    } else {
        send_server_key_exchange();
    }
}

void connection::send_server_key_exchange()
{
    if (auto handshake = server_kex_->server_key_exchange(client_random(), server_random())) {
        log_ << "Sending ServerKeyExchange" << std::endl;
        auto self = shared_from_this();
        send_handshake(*handshake, wrapped([self]() {
            self->send_server_hello_done();
        }, std::bind(&connection::handle_error, self, std::placeholders::_1)));
    } else {
        send_server_hello_done();
    }
}

void connection::send_server_hello_done()
{
    log_ << "Sending ServerHelloDone" << std::endl;
    auto self = shared_from_this();
    send_handshake(make_handshake(
        server_hello_done{}), wrapped([self] () {
            self->read_client_key_exchange();
        }, std::bind(&connection::handle_error, self, std::placeholders::_1)));
}

void connection::read_client_key_exchange() {
    log_ << "Reading ClientKeyExchange" << std::endl;
    auto self = shared_from_this();
    read_handshake(wrapped(
            [self] (tls::handshake&& handshake) {
                auto pre_master_secret = self->server_kex_->client_key_exchange(handshake);
                //self->log_ << "Premaster secret: " << util::base16_encode(pre_master_secret) << std::endl;
                self->set_pending_ciphers(pre_master_secret);
                self->log_ << "Reading ChangeCipherSpec" << std::endl;
                self->read_change_cipher_spec(wrapped(
                            [self] () {
                                self->log_ << "Sending ChangeCipherSpec" << std::endl;
                                self->send_change_cipher_spec(wrapped(
                                    [self] () {
                                        self->log_ << "Handshake done. Session id " << util::base16_encode(self->session_id().as_vector()) << std::endl;
                                        self->main_loop();
                                    },
                                    std::bind(&connection::handle_error, self, std::placeholders::_1)));
                            },
                            std::bind(&connection::handle_error, self, std::placeholders::_1)));
            },
            std::bind(&connection::handle_error, self, std::placeholders::_1)));
}

// TODO: Allow user to specificy what happens in this function
void connection::main_loop()
{
    auto self = shared_from_this();
    recv_app_data(wrapped(
        [self] (std::vector<uint8_t>&& data) {
            self->log_ << "Got app data: " << std::string(data.begin(), data.end());
            std::string text("Hello world!");
            self->send_app_data(std::vector<uint8_t>(text.begin(), text.end()), [self] (util::async_result<void> res) {
                res.get();
                // self->main_loop();
            });
        },
        std::bind(&connection::handle_error, self, std::placeholders::_1)));
}

class rsa_server_id : public server_id {
public:
    rsa_server_id(const std::vector<asn1cert>& certificate_chain, x509::rsa_private_key&& private_key)
        : certificate_chain_(certificate_chain)
        , private_key_(std::move(private_key)) {
    }

    const std::vector<asn1cert>& certificate_chain() const {
        return certificate_chain_;
    }

    x509::rsa_private_key private_key() const {
        return private_key_;
    }

private:
    std::vector<asn1cert> certificate_chain_;
    x509::rsa_private_key      private_key_;

    virtual bool supports(key_exchange_algorithm kex) const override;
    virtual std::unique_ptr<server_key_exchange_protocol> key_exchange_protocol(key_exchange_algorithm kex) const override;
};

class rsa_server_key_exchange_protocol : public server_key_exchange_protocol  {
public:
    explicit rsa_server_key_exchange_protocol(const rsa_server_id& server_id) : server_id_(server_id) {
    }

private:
    const rsa_server_id& server_id_;

    const std::vector<asn1cert>* do_certificate_chain() const override {
        return &server_id_.certificate_chain();
    }

    virtual std::unique_ptr<handshake> do_server_key_exchange(const random&, const random&) const override {
        return nullptr;
    }

    virtual std::vector<uint8_t> do_client_key_exchange(const handshake& handshake) const override {
        auto kex_rsa = get_as<client_key_exchange_rsa>(handshake);
        auto pre_master_secret = x509::pkcs1_decode(server_id_.private_key(), kex_rsa.encrypted_pre_master_secret.as_vector());
        FUNTLS_CHECK_BINARY((unsigned)pre_master_secret[0], ==, 0x03, "Invalid version in premaster secret");
        FUNTLS_CHECK_BINARY((unsigned)pre_master_secret[1], ==, 0x03, "Invalid version in premaster secret");
        return pre_master_secret;
    }
};

class dhe_rsa_server_key_exchange_protocol : public server_key_exchange_protocol {
public:
    explicit dhe_rsa_server_key_exchange_protocol(const rsa_server_id& server_id) : server_id_(server_id) {
        // 2048-bit MODP Group with 256-bit Prime Order Subgroup from RFC5114 section 2.3
        p_  = large_uint{"0x"
            "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2"
            "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30"
            "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD"
            "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
            "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C"
            "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E"
            "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9"
            "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
            "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3"
            "75F26375D7014103A4B54330C198AF126116D2276E11715F"
            "693877FAD7EF09CADB094AE91E1A1597"};
        g_ = large_uint{"0x"
            "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054"
            "07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555"
            "BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18"
            "A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
            "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83"
            "1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55"
            "A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14"
            "C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
            "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6"
            "184B523D1DB246C32F63078490F00EF8"};
        private_key_ = rand_positive_int_less(p_);
    }

private:
    const rsa_server_id& server_id_;
    static constexpr size_t key_size = 2048 / 8;
    large_uint           p_;
    large_uint           g_;
    large_uint           private_key_;

    const std::vector<asn1cert>* do_certificate_chain() const override {
        return &server_id_.certificate_chain();
    }

    virtual std::unique_ptr<handshake> do_server_key_exchange(const random& client_random, const random& server_random) const override {
        server_dh_params params;

        const large_uint Ys = powm(g_, private_key_, p_);

        //std::cout << "DHE server private key: " << std::hex << private_key_ << std::dec << std::endl;
        //std::cout << "Ys: " << std::hex << Ys << std::dec << std::endl;

        params.dh_p = x509::base256_encode(p_, key_size);   // The prime modulus used for the Diffie-Hellman operation.
        params.dh_g = x509::base256_encode(g_, key_size);   // The generator used for the Diffie-Hellman operation.
        params.dh_Ys = x509::base256_encode(Ys, key_size); // The server's Diffie-Hellman public value (g^X mod p).

        // Digitally sign client random, server random and the DHE parameters
        std::vector<uint8_t> digest_buf;
        append_to_buffer(digest_buf, client_random);
        append_to_buffer(digest_buf, server_random);
        append_to_buffer(digest_buf, params);

        const auto seq_buf = asn1::serialized(x509::digest_info{x509::algorithm_id{x509::id_sha256}, hash::sha256{}.input(digest_buf).result()});

        signed_signature signature;
        signature.hash_algorithm      = hash_algorithm::sha256;
        signature.signature_algorithm = signature_algorithm::rsa;
        signature.value               = x509::pkcs1_encode(server_id_.private_key(), seq_buf);

        return std::make_unique<handshake>(make_handshake(server_key_exchange_dhe{params, signature}));
    }

    virtual std::vector<uint8_t> do_client_key_exchange(const handshake& handshake) const override {
        auto kex_rsa = get_as<client_key_exchange_dhe_rsa>(handshake);
        //std::cout << "dh_Yc = " << util::base16_encode(kex_rsa.dh_Yc.as_vector()) << std::endl;

        const large_uint Yc = x509::base256_decode<large_uint>(kex_rsa.dh_Yc.as_vector());
        const large_uint Z  = powm(Yc, private_key_, p_);
        auto dh_Z  = x509::base256_encode(Z, key_size);
        //std::cout << "Negotaited key = " << util::base16_encode(dh_Z) << std::endl;

        return dh_Z;
    }
};

class ecdhe_rsa_server_key_exchange_protocol : public server_key_exchange_protocol {
public:
    ecdhe_rsa_server_key_exchange_protocol(const rsa_server_id& server_id) : server_id_(server_id) {
        d_U_ = rand_positive_int_less(curve().n); // private key
    }

private:
    const rsa_server_id& server_id_;
    const named_curve    curve_name_ = named_curve::secp256r1;
    large_uint           d_U_;

    const ec::curve curve() const {
        return curve_from_name(curve_name_);
    }

    uint32_t curve_size_bytes() const {
        const auto size = static_cast<uint32_t>(ilog256(curve().n));
        assert(size == ilog256(curve().p));
        return size;
    }

    const std::vector<asn1cert>* do_certificate_chain() const override {
        return &server_id_.certificate_chain();
    }

    virtual std::unique_ptr<handshake> do_server_key_exchange(const random& client_random, const random& server_random) const override {
        (void) client_random; (void) server_random;

        ec::point Ys = curve().mul(d_U_, curve().G); // ephemeral public key
        //std::cout << "Server private key: " << d_U_ << std::endl;
        //std::cout << "Server public key: " << Ys << std::endl;

        server_ec_dh_params params;
        params.curve_params.curve_type = ec_curve_type::named_curve;
        params.curve_params.named_curve = curve_name_;
        params.public_key = ec::point_to_bytes(Ys, curve_size_bytes());

        signed_signature signature;
        signature.hash_algorithm      = hash_algorithm::sha256;
        signature.signature_algorithm = signature_algorithm::rsa;


        std::vector<uint8_t> digest_buf;
        append_to_buffer(digest_buf, client_random);
        append_to_buffer(digest_buf, server_random);
        append_to_buffer(digest_buf, params);
        const auto seq_buf = asn1::serialized(x509::digest_info{x509::algorithm_id{x509::id_sha256}, hash::sha256{}.input(digest_buf).result()});
        signature.value               = x509::pkcs1_encode(server_id_.private_key(), seq_buf);

        return std::make_unique<handshake>(make_handshake(server_key_exchange_ec_dhe{params, signature}));
    }

    virtual std::vector<uint8_t> do_client_key_exchange(const handshake& handshake) const override {
        auto kex = get_as<client_key_exchange_ecdhe_ecdsa>(handshake);
        const auto Yc = ec::point_from_bytes(kex.ecdh_Yc.as_vector());
        std::cout << "SERVER: Client public key " << Yc << std::endl;

        ec::point P = curve().mul(d_U_, Yc);  // shared secret
        assert(curve().on_curve(P));

        std::cout << "Shared secret: " << P << std::endl;

        return x509::base256_encode(P.x, curve_size_bytes());
    }
};


bool rsa_server_id::supports(key_exchange_algorithm kex) const {
    return kex == key_exchange_algorithm::rsa || kex == key_exchange_algorithm::dhe_rsa || kex == key_exchange_algorithm::ecdhe_rsa;
}

std::unique_ptr<server_key_exchange_protocol> rsa_server_id::key_exchange_protocol(key_exchange_algorithm kex) const {
    switch (kex) {
    case key_exchange_algorithm::rsa:
        return std::unique_ptr<server_key_exchange_protocol>{new rsa_server_key_exchange_protocol{*this}};
    case key_exchange_algorithm::dhe_rsa:
        return std::unique_ptr<server_key_exchange_protocol>{new dhe_rsa_server_key_exchange_protocol{*this}};
    case key_exchange_algorithm::ecdhe_rsa:
        return std::unique_ptr<server_key_exchange_protocol>{new ecdhe_rsa_server_key_exchange_protocol{*this}};
    default:
        FUNTLS_CHECK_FAILURE("Usupported key exchange algorithm " + std::to_string(static_cast<int>(kex)));
    }
}

} } // namespace funtls::tls

#include <x509/x509_io.h>
tls::rsa_server_id get_server_id()
{
    static const char private_key[] = R"(
-----BEGIN PRIVATE KEY-----
MIICLgIBADANBgkqhkiG9w0BAQEFAASCAhgwggIUAgEAAkEAlUQe0RtIgCXpD0lkH5lco
pG/XrmJShcS462aLhucWEKjX5obKeHJ0NDEzpohGR/vZTTnYsABUp359WovMXD+ZQJAJQ
3gZa4/3AQOrTrOZkk8xx583O3lkUPsuHqZ/lXOp5ipZrDWznK6EcoXVe9IJWzoIDVQdij
ZuuBBIACXNkEPfwJAM45L/6COc4KaPqJlx6lgtDeVxrQtbxBdkTKO9G4ATsYFIno4fSgg
jrd31dGpzgXHckrKWT9u4zsALa8yP1Ed5wJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAADAUalZCSgsIQZuInQ3I4L0LeqTuHh9etZE8ehcuBamhwJAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAADGsPyBsTjUZ1jpPPsFwOi8eik2Tq7baHVG3AL69ya
CswJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACc7dNb7PXFwvlW/9uSHzOs
9oelPYpaRXldYRIRDJNG6wJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABhf
qZJDN4j7pg/q/iUJDrhSP0Ru87iPcejoB0qA2sx5QJAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAACdt2KWqpWDI9KyNS/jMho4UBocb4Ax3E/2TNRLMsRtwg==
-----END PRIVATE KEY-----)";
    static const char certificate[] = 
"MIIBUjCB/aADAgECAgEBMA0GCSqGSIb3DQEBBAUAMBQxEjAQBgNVBAMWCWxvY2Fs"
"aG9zdDAaFwsxNTExMDgwMDAwWhcLMjUxMTA4MDAwMFowFDESMBAGA1UEAxYJbG9j"
"YWxob3N0MIGbMA0GCSqGSIb3DQEBAQUAA4GJADCBhQJBAJVEHtEbSIAl6Q9JZB+Z"
"XKKRv165iUoXEuOtmi4bnFhCo1+aGynhydDQxM6aIRkf72U052LAAVKd+fVqLzFw"
"/mUCQCUN4GWuP9wEDq06zmZJPMcefNzt5ZFD7Lh6mf5VzqeYqWaw1s5yuhHKF1Xv"
"SCVs6CA1UHYo2brgQSAAlzZBD38wDQYJKoZIhvcNAQEEBQADQQBMhEJLmCS0dkS8"
"NKWutTJIaoON+jkLOnIXauB3f2XXQ5J+Bm8HquJHPGx4CGG/5SasJr/RBOzZN6Mv"
"L3SPTuuT";

    auto pki = x509::read_pem_private_key_from_string(private_key);
    assert(pki.version.as<int>() == 0);
    assert(pki.algorithm.id() == x509::id_rsaEncryption);

    return tls::rsa_server_id{{util::base64_decode(certificate, sizeof(certificate)-1)}, x509::rsa_private_key_from_pki(pki)};
}

#if defined(OPENSSL_TEST) || defined(SELF_TEST)
#define TESTING
#include <thread>
#endif

#ifdef SELF_TEST
#include "https_fetch.h"
#elif defined(OPENSSL_TEST)
#include <stdio.h> // popen
#ifdef _MSC_VER
#define popen _popen
#define pclose _pclose
#endif
#endif

int main(int argc, char* argv[])
{
    int wanted_port = 0;
    if (argc > 1) {
        std::istringstream iss(argv[1]);
        if (!(iss >> wanted_port) || wanted_port < 0 || wanted_port > 65535) {
            std::cerr << "Invalid port " << argv[1] << "" << std::endl;
            return 1;
        }
    }
    boost::asio::io_service        io_service;
    boost::asio::ip::tcp::acceptor acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), static_cast<uint16_t>(wanted_port)));

    struct accept_state {
        accept_state(boost::asio::io_service& io_service) : socket(io_service) {
        }
        boost::asio::ip::tcp::socket socket;
    };

    auto server_id = get_server_id();

    std::function<void (void)> start_accept = [&acceptor, &start_accept, &server_id] {
        auto state = std::make_shared<accept_state>(acceptor.get_io_service());
        acceptor.async_accept(state->socket,
            [state, &start_accept, &server_id] (const boost::system::error_code& ec) {
                if (ec) {
                    std::cout << "Accept failed: " << ec << std::endl;
                } else {
                    std::ostringstream oss;
                    oss << state->socket.remote_endpoint();
                    tls::connection::make(oss.str(), make_tls_stream(std::move(state->socket)), {&server_id});
                }
                start_accept();
            });
    };

    start_accept();
    std::cout << "Server running: " << acceptor.local_endpoint() << std::endl;

#ifdef TESTING
    unsigned short port = acceptor.local_endpoint().port();
    std::exception_ptr eptr = nullptr;
    std::thread client_thread([&] {
            boost::asio::io_service::work work(io_service); // keep the io_service running as long as the thread does

            try {
#ifdef OPENSSL_TEST
                FUNTLS_CHECK_BINARY(argc, ==, 3, "Invalid arguments to test");
                const std::string cipher = "RC4-MD5";
                std::ostringstream cmd;
                cmd << "echo HELLO WORLD | " << argv[2] << " s_client -debug -msg -cipher " << cipher <<  " -connect localhost:" << port << " 2>&1";
                const auto cmdline = cmd.str();
                io_service.post([cmdline] {
                        std::cout << "Running command: " << cmdline << std::endl;
                        });
                std::unique_ptr<FILE, decltype(&::pclose)> f{popen(cmdline.c_str(), "r"), &::pclose};
                assert(f);

                char buffer[1024];
                while (fgets(buffer, sizeof(buffer), f.get())) {
                    std::string s=buffer;
                    io_service.post([s] {
                            std::cout << "[openssl] " << s;
                            });
                }
                const bool eof = feof(f.get()) != 0;
                io_service.post([eof] {
                        std::cout << "openssl command finished - " << (eof ? "EOF" : "Other error encountered") << "\n";
                        FUNTLS_ASSERT_EQUAL(eof, true);
                        });
#elif defined(SELF_TEST)
                x509::trust_store ts;

                const std::vector<tls::cipher_suite> cipher_suites{
                    //tls::cipher_suite::ecdhe_ecdsa_with_aes_256_gcm_sha384,
                    //tls::cipher_suite::ecdhe_ecdsa_with_aes_128_gcm_sha256,

                    tls::cipher_suite::ecdhe_rsa_with_aes_256_cbc_sha,
                    tls::cipher_suite::ecdhe_rsa_with_aes_128_cbc_sha,

                    tls::cipher_suite::ecdhe_rsa_with_aes_256_gcm_sha384,
                    tls::cipher_suite::ecdhe_rsa_with_aes_128_gcm_sha256,

                    tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha256,
                    tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha256,
                    tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha,
                    tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha,
                    tls::cipher_suite::dhe_rsa_with_3des_ede_cbc_sha,

                    tls::cipher_suite::rsa_with_aes_256_gcm_sha384,
                    tls::cipher_suite::rsa_with_aes_128_gcm_sha256,
                    tls::cipher_suite::rsa_with_aes_256_cbc_sha256,
                    tls::cipher_suite::rsa_with_aes_128_cbc_sha256,
                    tls::cipher_suite::rsa_with_aes_256_cbc_sha,
                    tls::cipher_suite::rsa_with_aes_128_cbc_sha,
                    tls::cipher_suite::rsa_with_3des_ede_cbc_sha,
                    tls::cipher_suite::rsa_with_rc4_128_sha,
                    tls::cipher_suite::rsa_with_rc4_128_md5,
                };

                for (const auto& cs: cipher_suites) {
                    io_service.post([cs] { std::cout << "=== Testing " << cs << " ===" << std::endl; });
                    std::string res;
                    util::ostream_adapter fetch_log{[&io_service](const std::string& s) { io_service.post([s] { std::cout << "Client: " << s; }); }};
                    https_fetch("localhost", std::to_string(port), "/", {cs}, ts, [&res](const std::vector<uint8_t>& data) {
                        res.insert(res.end(), data.begin(), data.end());
                    }, fetch_log);
                    io_service.post([res] {
                        std::cout << "Got result: \"" << res << "\"" << std::endl;
                        FUNTLS_ASSERT_EQUAL("Hello world!", res);
                    });
                }
#else
#error What are we testing???
#endif
            } catch (...) {
                eptr = std::current_exception();
            }
            io_service.post([&io_service] { io_service.stop(); });
    });
#endif

    int retval = 1;
    try {
        io_service.run();
#ifdef TESTING
        if (eptr) std::rethrow_exception(eptr);
#endif
        retval = 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
    }
#ifdef TESTING
    client_thread.join();
#endif
    return retval;
}

