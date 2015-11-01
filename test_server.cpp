#include <iostream>
#include <stdio.h> // popen

#include <util/test.h>
#include <util/base_conversion.h>
#include <tls/tls_base.h>
#include <tls/tls_ser.h>
#include <int_util/int.h>
#include <int_util/int_util.h>
#include <x509/x509_rsa.h>
#include <asio_stream_adapter.h>

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
    std::string                                     name_;
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
    , name_(name)
    , server_ids_(server_ids)
    , server_kex_(nullptr)
{
    std::cout << name_ << ": Connected\n";
    assert(!server_ids_.empty());
}

connection::~connection()
{
    std::cout << name_ << ": Conncetion dropped\n";
}

void connection::handle_error(std::exception_ptr e) const
{
    assert(e);
    std::ostringstream msg;
    msg << name_ << ": ";
    msg << "[!!!] ";
    try {
        std::rethrow_exception(e);
    } catch (const std::exception& e) {
        msg << e.what();
    } catch (...) {
        msg << "Unknown exception type caught";
    }
    msg << "\n";
    std::cerr << msg.str();
}


void connection::read_client_hello() {
    std::cout << name_ << ": Reading ClientHello\n";
    auto self = shared_from_this();
    read_handshake(wrapped(
            [self] (tls::handshake&& handshake) {
                auto client_hello = get_as<tls::client_hello>(handshake);
                std::cout << self->name_ << ": Got client hello\n";
                std::cout << self->name_ << ": version " << client_hello.client_version << "\n";
                std::cout << self->name_ << ": session " << util::base16_encode(client_hello.session_id.as_vector()) << "\n";
                std::cout << self->name_ << ": cipher_suites:";
                for (auto cs : client_hello.cipher_suites.as_vector()) {
                    std::cout << " " << cs;
                }
                std::cout << "\n";
                std::cout << self->name_ << ": compression_methods:";
                for (auto cm : client_hello.compression_methods.as_vector()) {
                    std::cout << " " << (int)cm;
                }
                std::cout << "\n";
                std::cout << self->name_ << ": extensions:\n";
                for (const auto& ext : client_hello.extensions) {
                    std::cout << ext.type << " " << util::base16_encode(ext.data.as_vector())  << "\n";
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
                std::cout << self->name_ << ": Negotatiated cipher: " << cipher << std::endl;
                assert(self->server_kex_);

                self->send_server_hello();
            },
            std::bind(&connection::handle_error, self, std::placeholders::_1)));
}

void connection::send_server_hello()
{
    std::cout << name_ << ": Sending ServerHello\n";
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
        std::cout << name_ << ": Sending ServerCertificate\n";
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
        std::cout << name_ << ": Sending ServerKeyExchange\n";
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
    std::cout << name_ << ": Sending ServerHelloDone\n";
    auto self = shared_from_this();
    send_handshake(make_handshake(
        server_hello_done{}), wrapped([self] () {
            self->read_client_key_exchange();
        }, std::bind(&connection::handle_error, self, std::placeholders::_1)));
}

void connection::read_client_key_exchange() {
    std::cout << name_ << ": Reading ClientKeyExchange\n";
    auto self = shared_from_this();
    read_handshake(wrapped(
            [self] (tls::handshake&& handshake) {
                auto pre_master_secret = self->server_kex_->client_key_exchange(handshake);
                std::cout << self->name_ << ": Premaster secret: " << util::base16_encode(pre_master_secret) << std::endl;
                self->set_pending_ciphers(pre_master_secret);
                std::cout << self->name_ << ": Reading ChangeCipherSpec\n";
                self->read_change_cipher_spec(wrapped(
                            [self] () {
                                std::cout << self->name_ << ": Sending ChangeCipherSpec\n";
                                self->send_change_cipher_spec(wrapped(
                                    [self] () {
                                        std::cout << self->name_ << ": Handshake done. Session id " << util::base16_encode(self->session_id().as_vector()) << std::endl;
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
            std::cout << self->name_ << ": Got app data: " << std::string(data.begin(), data.end());
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

    virtual bool supports(key_exchange_algorithm kex) const override {
        return kex == key_exchange_algorithm::rsa || kex == key_exchange_algorithm::dhe_rsa;
    }

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

        std::cout << "DHE server private key: " << std::hex << private_key_ << std::dec << std::endl;
        std::cout << "Ys: " << std::hex << Ys << std::dec << std::endl;

        params.dh_p = x509::base256_encode(p_, key_size);   // The prime modulus used for the Diffie-Hellman operation.
        params.dh_g = x509::base256_encode(g_, key_size);   // The generator used for the Diffie-Hellman operation.
        params.dh_Ys = x509::base256_encode(Ys, key_size); // The server's Diffie-Hellman public value (g^X mod p).


        std::vector<uint8_t> digest_buf;
        append_to_buffer(digest_buf, client_random);
        append_to_buffer(digest_buf, server_random);
        append_to_buffer(digest_buf, params);

        const auto& algo_oid = x509::id_sha256;
        const auto digest = hash::sha256{}.input(digest_buf).result();

        // DigestInfo ::= SEQUENCE {
        //   digestAlgorithm AlgorithmIdentifier,
        //   digest OCTET STRING }

        const auto seq_buf = serialized_sequence(asn1::identifier::constructed_sequence,
            serialized_sequence(asn1::identifier::constructed_sequence, algo_oid, std::vector<uint8_t>{static_cast<uint8_t>(asn1::identifier::null), 0}),
            asn1::octet_string{digest});

        signed_signature signature;
        signature.hash_algorithm      = hash_algorithm::sha256;
        signature.signature_algorithm = signature_algorithm::rsa;
        signature.value               = x509::pkcs1_encode(server_id_.private_key(), seq_buf);

        return std::make_unique<handshake>(make_handshake(server_key_exchange_dhe{params, signature}));
    }

    virtual std::vector<uint8_t> do_client_key_exchange(const handshake& handshake) const override {
        auto kex_rsa = get_as<client_key_exchange_dhe_rsa>(handshake);
        std::cout << "dh_Yc = " << util::base16_encode(kex_rsa.dh_Yc.as_vector()) << std::endl;

        const large_uint Yc = x509::base256_decode<large_uint>(kex_rsa.dh_Yc.as_vector());
        const large_uint Z  = powm(Yc, private_key_, p_);
        auto dh_Z  = x509::base256_encode(Z, key_size);
        std::cout << "Negotaited key = " << util::base16_encode(dh_Z) << std::endl;

        return dh_Z;
    }
};

std::unique_ptr<server_key_exchange_protocol> rsa_server_id::key_exchange_protocol(key_exchange_algorithm kex) const {
    switch (kex) {
    case key_exchange_algorithm::rsa:
        return std::unique_ptr<server_key_exchange_protocol>{new rsa_server_key_exchange_protocol{*this}};
    case key_exchange_algorithm::dhe_rsa:
        return std::unique_ptr<server_key_exchange_protocol>{new dhe_rsa_server_key_exchange_protocol{*this}};
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
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCedvFnN8tdl7MP
fAHpl02a+QxXOaCDybGovMZRBQ2rL8Ti7JkEeJiEY4Qz9ZJ9WgQB3Tll9KAueRBz
dmUTOptqSwwx8Ykm3R65lbFljKT04hj3yvCaHg5j+UnzMRIqJ9W8f+EVAGKIG0rp
hTYdpzJpnbSHU8y31Y8THmjgZSyTwSvsP+U1pB/Mt6SSQD7SWIwABveWx6gcCEe0
yE0L5oUISuyR7rRtoBPaSTcL5y3fu2Ez9wc8VVBTBx6wiNqs3BAsBssQADD6sokW
G9AbPchLfkajkb77tX/0GXrnam8oaC5QSOO6SI5vybdIcqAzc5EXN+uEKM/q9vuQ
Sdcr3SelAgMBAAECggEAZPG4DdyI+/Hq6u4/+aGcmiAUMGxRSCJvveGjI3Fop6gi
b7vwLdz0q0EJsl+5FYkGDHn0WnJep7wPMr403O70md18w0Pt7oflTquA+gOCAU0W
QqNQaZzD5gOji/uyapA9o3qC03IPUkywh9mIA5PClW0U1zAWtPSh07gHbwqEPwpK
XVBqfZgHHeqdkli+7uLew00p+kZwDW49CVhDoY8LtaO2a7jebOnm4Mhop+wZjqVy
I0RSOr1Va9l0Zqoh9At7dluxEeI20uts9jkwQcsfaf4rn1M8f4zkHc3GB4ExrOaF
WTfzzBrbtzxWlmryYLhRBlLwcTREKF5M25UizgE2AQKBgQDNMOifb+xGXji0WPnC
BRNa96KDgNYpFfWQUaqle2eSMSuyEtsAMAhlF2tkiwKX7umrOE99bitrZ3jPm+Ye
ekB0C3aKwW+94jxbqYNpnO9s2pIg/jVXCQxaW3SnqfnTrihIMNg0P2gnh0xcdKQM
Kq9tBfeXUkhEyBHX68dBCvP6RQKBgQDFtAn8UqQsZflWOvQdPhatFSwH645jZ+bY
TnSG9JQoW0IuQqTfcr4xbjltDZsp+cDngD0HLJ/Gf33sLrfTVsDlSIZk935qxgiJ
lzyNR1Fd4xdUx6I9Gs4DwWXjE8u/IOq/fhxZ/8c2c8jXVvlTbeEMgRNA9sKP0TnT
ysMB1jj94QKBgAfZZhyrQGOUuSCVAsDcRthE/s9+/zJFJ8akiR2ZceXSwbQnKn+A
VuHfGnmXI7tCJWgqWEgZDconBCUU9qGV1Z9azOcT7T1bSSnMez1wBmyok8x1TP8O
Vo2iT/0V8Hubfuj8DVk6T7arY01qHNhmTZ2jC8ybFi6jZKNY3p9rVtftAoGAMMOw
ttkXf5ADiT5vWgsngre3LZjvfRtyuCXZ3jPTm4Su9UQg8LCXsw+SAJEblaXx6+gY
pX1fR5HI2InJc8pxN9zEsYDOYL3J+04fdGWD71mFNrcrEFFdQVXhsLoARntzC5qq
mZRaadbzUhI021w951yrCBoVcW3VCqV3pitV0WECgYBr/upn5ouDPAjJUZzt14nQ
1daVE0xqt7S1Z2ks46Low1KJyrEzF2tKlnMeV1l9pgPDjHKzCkmYR4SZpUfSq2IU
/Wm8TRASrW+ablQHzPP+TsUSUt6sY/IpxSjfHUHO2w1CKhtLfQU892b9By47qB/L
AZokDceX95yJnwKqa6SzgQ==
-----END PRIVATE KEY-----
)";
    static const char certificate[] = 
"MIIC+zCCAeOgAwIBAgIJAN1DsbDMyeJ9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV"
"BAMMCWxvY2FsaG9zdDAeFw0xNTA2MTMxOTI2MzJaFw0yNTA2MTAxOTI2MzJaMBQx"
"EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC"
"ggEBAJ528Wc3y12Xsw98AemXTZr5DFc5oIPJsai8xlEFDasvxOLsmQR4mIRjhDP1"
"kn1aBAHdOWX0oC55EHN2ZRM6m2pLDDHxiSbdHrmVsWWMpPTiGPfK8JoeDmP5SfMx"
"Eion1bx/4RUAYogbSumFNh2nMmmdtIdTzLfVjxMeaOBlLJPBK+w/5TWkH8y3pJJA"
"PtJYjAAG95bHqBwIR7TITQvmhQhK7JHutG2gE9pJNwvnLd+7YTP3BzxVUFMHHrCI"
"2qzcECwGyxAAMPqyiRYb0Bs9yEt+RqORvvu1f/QZeudqbyhoLlBI47pIjm/Jt0hy"
"oDNzkRc364Qoz+r2+5BJ1yvdJ6UCAwEAAaNQME4wHQYDVR0OBBYEFNcy1UunV/YV"
"AUnGhgoDcZnOmnNVMB8GA1UdIwQYMBaAFNcy1UunV/YVAUnGhgoDcZnOmnNVMAwG"
"A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEjitUaPNsdB9QMSgcAvzr1L"
"HdVgJQccTsNrqulfvflG3f1XXrKZkzJMArvP4za/BMy/ug9IipIXWpcNTOCfnJbo"
"squiyj/bLLn4ZgLV6wKPW25tbJF6u3FS6+O2MdfyU9SR28y/UoFKVCLBRt3tflph"
"2Xfp7zn3bLw6jgAAVPtJ+BdNwdIaYy14x5pINHum+99iYEvVolPcrPbUlQk7Y3jS"
"sSUcN2EUHHWkG/NfxeMu4A1W4Pxp5u4Zkg9OGlfrF7uTK9kZMOx5nCa7cE75gAb3"
"WMVDXABQK4UaNGxPRhDUAy7u8NqtePjmWGuBzEorqsT9baf7SfdYpGlemBglYWM=";

    auto pki = x509::read_pem_private_key_from_string(private_key);
    assert(pki.version.as<int>() == 0);
    assert(pki.algorithm == x509::id_rsaEncryption);

    return tls::rsa_server_id{{util::base64_decode(certificate, sizeof(certificate)-1)}, x509::rsa_private_key_from_pki(pki)};
}

#if defined(OPENSSL_TEST) || defined(SELF_TEST)
#define TESTING
#include <thread>
#endif

#ifdef SELF_TEST
#include "tls_fetch.h"
#endif

int main(int argc, char* argv[])
{
    int wanted_port = 0;
    if (argc > 1) {
        std::istringstream iss(argv[1]);
        if (!(iss >> wanted_port) || wanted_port < 0 || wanted_port > 65535) {
            std::cerr << "Invalid port " << argv[1] << "\n";
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
#ifndef OPENSSL_TEST
                start_accept();
#endif
            });
    };

    start_accept();
    std::cout << "Server running: " << acceptor.local_endpoint() << std::endl;

#ifdef TESTING
    unsigned short port = acceptor.local_endpoint().port();
    std::exception_ptr eptr = nullptr;
    std::thread client_thread([port, &io_service, &eptr] {
            boost::asio::io_service::work work(io_service); // keep the io_service running as long as the thread does

            try {
#ifdef OPENSSL_TEST
                std::ostringstream cmd;
                cmd << "echo HELLO WORLD | openssl s_client -debug -msg -connect localhost:" << port << " 2>&1";
                io_service.post([&] {
                        std::cout << "Running command: " << cmd.str() << std::endl;
                        });
                std::unique_ptr<FILE, decltype(&::fclose)> f{popen(cmd.str().c_str(), "r"), &::fclose};
                assert(f);

                char buffer[1024];
                while (fgets(buffer, sizeof(buffer), f.get())) {
                    std::string s=buffer;
                    io_service.post([s] {
                            std::cout << "[openssh] " << s;
                            });
                }
#elif defined(SELF_TEST)
                x509::trust_store ts;

                const std::vector<tls::cipher_suite> cipher_suites{
                    //tls::cipher_suite::ecdhe_ecdsa_with_aes_256_gcm_sha384,
                    //tls::cipher_suite::ecdhe_ecdsa_with_aes_128_gcm_sha256,
                    //tls::cipher_suite::ecdhe_rsa_with_aes_256_gcm_sha384,
                    //tls::cipher_suite::ecdhe_rsa_with_aes_128_gcm_sha256,
                    
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
                    std::cout << "=== Testing " << cs << " ===" << std::endl;
                    std::string res;
                    tls_fetch("localhost", std::to_string(port), "/", {cs}, ts, [&res](const std::vector<uint8_t>& data) {
                        res.insert(res.end(), data.begin(), data.end());
                    });
                    std::cout << "Got result: \"" << res << "\"" << std::endl;
                    FUNTLS_ASSERT_EQUAL("Hello world!", res);
                }
#else
#error What are we testing???
#endif
            } catch (...) {
                eptr = std::current_exception();
            }
            io_service.stop();
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

