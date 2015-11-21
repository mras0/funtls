#include <tls/tls_server_rsa_kex.h>
#include <tls/tls_ser.h>
#include <tls/tls_ecc.h>
#include <x509/x509_rsa.h>
#include <x509/x509_ec.h>
#include <int_util/int_util.h>
#include <util/test.h>

namespace funtls { namespace tls {

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

    virtual bool do_supports(key_exchange_algorithm kex) const override;
    virtual std::unique_ptr<server_key_exchange_protocol> do_key_exchange_protocol(key_exchange_algorithm kex) const override;
};

std::unique_ptr<server_id> make_rsa_server_id(const std::vector<asn1cert>& certificate_chain, x509::rsa_private_key&& private_key) {
    return std::unique_ptr<server_id>{new rsa_server_id{certificate_chain, std::move(private_key)}};
}

class rsa_server_key_exchange_protocol : public server_key_exchange_protocol {
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
        (void)client_random; (void)server_random;

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
        //std::cout << "SERVER: Client public key " << Yc << std::endl;

        ec::point P = curve().mul(d_U_, Yc);  // shared secret
        assert(curve().on_curve(P));

        //std::cout << "Shared secret: " << P << std::endl;

        return x509::base256_encode(P.x, curve_size_bytes());
    }
};


bool rsa_server_id::do_supports(key_exchange_algorithm kex) const {
    return kex == key_exchange_algorithm::rsa || kex == key_exchange_algorithm::dhe_rsa || kex == key_exchange_algorithm::ecdhe_rsa;
}

std::unique_ptr<server_key_exchange_protocol> rsa_server_id::do_key_exchange_protocol(key_exchange_algorithm kex) const {
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