#include "tls_kex.h"
#include <x509/x509_rsa.h>
#include <x509/x509_ec.h>
#include <util/test.h>
#include <util/base_conversion.h>
#include <int_util/int_util.h>
#include "tls_ecc.h"
#include <ec/ec.h>

#include <iostream>

#include <int_util/int.h>

using namespace funtls;

namespace {

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

void verify_signature_rsa(const x509::certificate& cert, const tls::signed_signature& sig, const std::vector<uint8_t>& digest_buf)
{
    std::cout << "Verify RSA " << sig.hash_algorithm << " signature" << std::endl;
    auto public_key = x509::rsa_public_key_from_certificate(cert);
    FUNTLS_CHECK_BINARY(sig.signature_algorithm, ==, tls::signature_algorithm::rsa, "");
    const auto digest = x509::pkcs1_decode(public_key, sig.value.as_vector());
    FUNTLS_CHECK_BINARY(digest.digest_algorithm.null_parameters(), ==, true, "Invalid algorithm parameters");
    FUNTLS_CHECK_BINARY(hash_algorithm_from_oid(digest.digest_algorithm.id()), ==, sig.hash_algorithm, "");

    const auto calced_digest = get_hash(sig.hash_algorithm).input(digest_buf).result();
    FUNTLS_CHECK_BINARY(calced_digest.size(), ==, digest.digest.size(), "Wrong digest size");
    if (!std::equal(calced_digest.begin(), calced_digest.end(), digest.digest.begin())) {
        throw std::runtime_error("Digest mismatch in " + std::string(__PRETTY_FUNCTION__) + " Calculated: " +
                util::base16_encode(calced_digest) + " Expected: " +
                util::base16_encode(digest.digest));
    }
}

void verify_signature_ecdsa(const x509::certificate& cert, const tls::signed_signature& sig, const std::vector<uint8_t>& digest_buf)
{
    std::cout << "Verify ECDSA " << sig.hash_algorithm << " signature" << std::endl;
    auto public_key = x509::ec_public_key_from_certificate(cert);
    const auto& curve = x509::curve_from_name(public_key.curve_name);

    FUNTLS_CHECK_BINARY(tls::signature_algorithm::ecdsa, ==, sig.signature_algorithm, "Invalid key exchange algorithm");
    const auto ecdsa_sig = x509::ecdsa_sig_value::parse(sig.value.as_vector());
    auto H = get_hash(sig.hash_algorithm).input(digest_buf).result();
    const auto max_size = ilog256(curve.n);
    if (H.size() > max_size) {
        H.erase(H.begin() + max_size, H.end());
    }
    const auto e = x509::base256_decode<ec::field_elem>(H);

    assert(e >= 0 && e < curve.n);
    curve.verify_ecdsa_signature(public_key.Q, ecdsa_sig.r, ecdsa_sig.s, e);
}

} // unnamed namespace

namespace funtls { namespace tls {

class rsa_client_kex_protocol : public client_key_exchange_protocol {
public:
    rsa_client_kex_protocol(protocol_version protocol_version)
        : protocol_version_(protocol_version) {
    }

private:
    protocol_version protocol_version_;

    virtual result_type do_result() const override;
};

class dhe_rsa_client_kex_protocol : public client_key_exchange_protocol {
public:
    dhe_rsa_client_kex_protocol(const random& client_random, const random& server_random);

private:
    std::unique_ptr<server_dh_params> server_dh_params_;
    std::vector<uint8_t> digest_buf;

    virtual void do_server_key_exchange(const handshake& ske) override;
    virtual result_type do_result() const override;
};

class ecdhe_client_kex_protocol : public client_key_exchange_protocol {
public:
    ecdhe_client_kex_protocol(signature_algorithm sig_algo, const random& client_random, const random& server_random);

private:
    struct params {
        named_curve curve_name;
        ec::point   Q;
    };
    std::unique_ptr<params>         params_;
    std::vector<uint8_t>            digest_buf_;
    void (*verify_signature_)(const x509::certificate& cert, const signed_signature& sig, const std::vector<uint8_t>& digest_buf);
    virtual void do_server_key_exchange(const handshake& ske) override;
    virtual result_type do_result() const override;
};

std::unique_ptr<client_key_exchange_protocol> make_client_key_exchange_protocol(key_exchange_algorithm kex_algo, protocol_version ver, const random& client_random, const random& server_random)
{
    if (kex_algo == key_exchange_algorithm::rsa) {
        return std::unique_ptr<client_key_exchange_protocol>(new rsa_client_kex_protocol(ver));
    } else if (kex_algo == key_exchange_algorithm::dhe_rsa) {
        return std::unique_ptr<client_key_exchange_protocol>(new dhe_rsa_client_kex_protocol(client_random, server_random));
    } else if (kex_algo == key_exchange_algorithm::ecdhe_ecdsa) {
        return std::unique_ptr<client_key_exchange_protocol>(new ecdhe_client_kex_protocol(signature_algorithm::ecdsa, client_random, server_random));
    } else if (kex_algo == key_exchange_algorithm::ecdhe_rsa) {
        return std::unique_ptr<client_key_exchange_protocol>(new ecdhe_client_kex_protocol(signature_algorithm::rsa, client_random, server_random));
    } else {
        FUNTLS_CHECK_FAILURE("Internal error: Unsupported KeyExchangeAlgorithm " + std::to_string((int)kex_algo));
    }
}

void client_key_exchange_protocol::certificate_list(const std::vector<x509::certificate>& certificate_list)
{
    assert(!server_certificate_);
    assert(!certificate_list.empty());
    server_certificate_.reset(new x509::certificate(certificate_list.front()));
}

const x509::certificate& client_key_exchange_protocol::server_certificate() const
{
    if (!server_certificate_) FUNTLS_CHECK_FAILURE("No server certificate provided");
    return *server_certificate_;
}

void client_key_exchange_protocol::do_server_key_exchange(const handshake&)
{
    FUNTLS_CHECK_FAILURE("Not expecting ServerKeyExchange message");
}

rsa_client_kex_protocol::result_type rsa_client_kex_protocol::do_result() const
{
    auto server_pk = rsa_public_key_from_certificate(server_certificate());
    // OK, now it's time to do ClientKeyExchange
    // Since we're doing RSA, we'll be sending the EncryptedPreMasterSecret
    // Prepare pre-master secret (version + 46 random bytes)
    std::vector<uint8_t> pre_master_secret(master_secret_size);
    pre_master_secret[0] = protocol_version_.major;
    pre_master_secret[1] = protocol_version_.minor;
    util::get_random_bytes(&pre_master_secret[2], pre_master_secret.size()-2);

    const auto C = x509::pkcs1_encode(server_pk, pre_master_secret);
    client_key_exchange_rsa client_key_exchange{vector<uint8,0,(1<<16)-1>{C}};
    return std::make_pair(std::move(pre_master_secret), make_handshake(client_key_exchange));
}

dhe_rsa_client_kex_protocol::dhe_rsa_client_kex_protocol(const random& client_random, const random& server_random)
{
    append_to_buffer(digest_buf, client_random);
    append_to_buffer(digest_buf, server_random);
}

void dhe_rsa_client_kex_protocol::do_server_key_exchange(const handshake& ske)
{
    assert(!server_dh_params_);
    auto kex = get_as<server_key_exchange_dhe>(ske);
    append_to_buffer(digest_buf, kex.params);
    verify_signature_rsa(server_certificate(), kex.signature, digest_buf);
    server_dh_params_.reset(new server_dh_params(kex.params));
}

dhe_rsa_client_kex_protocol::result_type dhe_rsa_client_kex_protocol::do_result() const
{
    if (!server_dh_params_) FUNTLS_CHECK_FAILURE("");
    const large_uint p  = x509::base256_decode<large_uint>(server_dh_params_->dh_p.as_vector());
    const large_uint g  = x509::base256_decode<large_uint>(server_dh_params_->dh_g.as_vector());
    const large_uint Ys = x509::base256_decode<large_uint>(server_dh_params_->dh_Ys.as_vector());
    const size_t key_size = server_dh_params_->dh_p.size();
    const large_uint private_key = rand_positive_int_less(p);

    //std::cout << "DHE client private key: " << std::hex << private_key << std::dec << std::endl;

    const large_uint Yc = powm(g, private_key, p);
    const auto dh_Yc  = x509::base256_encode(Yc, key_size);

    //std::cout << "dh_Yc = " << util::base16_encode(dh_Yc) << std::endl;

    client_key_exchange_dhe_rsa client_key_exchange{dh_Yc};
    auto handshake = make_handshake(client_key_exchange);

    const large_uint Z = powm(Ys, private_key, p);
    auto dh_Z  = x509::base256_encode(Z, key_size);
    //std::cout << "Negotaited key = " << util::base16_encode(dh_Z) << std::endl;
    return std::make_pair(std::move(dh_Z), std::move(handshake));
}

ecdhe_client_kex_protocol::ecdhe_client_kex_protocol(signature_algorithm sig_algo, const random& client_random, const random& server_random)
{
    append_to_buffer(digest_buf_, client_random);
    append_to_buffer(digest_buf_, server_random);
    if (sig_algo == signature_algorithm::rsa) {
        verify_signature_ = &verify_signature_rsa;
    } else if (sig_algo == signature_algorithm::ecdsa) {
        verify_signature_ = &verify_signature_ecdsa;
    } else {
        std::ostringstream msg;
        msg << "Unsupported signature algorithm " << sig_algo;
        FUNTLS_CHECK_FAILURE(msg.str());
    }
}

void ecdhe_client_kex_protocol::do_server_key_exchange(const handshake& ske) {
    assert(params_ == nullptr);
    auto kex = get_as<server_key_exchange_ec_dhe>(ske);
    std::cout << "curve_type=" << kex.params.curve_params.curve_type << std::endl;
    FUNTLS_CHECK_BINARY(kex.params.curve_params.curve_type, ==, ec_curve_type::named_curve, "Unsupported curve type");
    std::cout << "named_curve=" << kex.params.curve_params.named_curve << std::endl;
    const auto& curve = curve_from_name(kex.params.curve_params.named_curve);
    const auto ephemeral_public_key = ec::point_from_bytes(kex.params.public_key.as_vector());
    std::cout << "ephemeral_public_key=" << ephemeral_public_key << std::endl;
    curve.check_public_key(ephemeral_public_key);
    append_to_buffer(digest_buf_, kex.params);
    verify_signature_(server_certificate(), kex.signature, digest_buf_);
    params_.reset(new params{kex.params.curve_params.named_curve, ephemeral_public_key});
}

ecdhe_client_kex_protocol::result_type ecdhe_client_kex_protocol::do_result() const {
    if (!params_) FUNTLS_CHECK_FAILURE("");
    const auto& curve = curve_from_name(params_->curve_name);

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

} } // namespace funtls::tls
