#ifndef TLS_CIPHERS_H_INCLUDED
#define TLS_CIPHERS_H_INCLUDED

#include <iosfwd>
#include <cstdint>
#include <cassert>
#include <memory>
#include <hash/hash.h>

namespace funtls { namespace asn1 {
    class object_id;
} } // namespace funtls::asn1

namespace funtls { namespace tls {

enum class cipher_suite : uint16_t {
    null_with_null_null                  = 0x0000,

    rsa_with_null_md5                    = 0x0001,
    rsa_with_null_sha                    = 0x0002,
    rsa_with_null_sha256                 = 0x003B,
    rsa_with_rc4_128_md5                 = 0x0004,
    rsa_with_rc4_128_sha                 = 0x0005,
    rsa_with_3des_ede_cbc_sha            = 0x000A,
    rsa_with_aes_128_cbc_sha             = 0x002F,
    rsa_with_aes_256_cbc_sha             = 0x0035,
    rsa_with_aes_128_cbc_sha256          = 0x003C,
    rsa_with_aes_256_cbc_sha256          = 0x003D,

    dh_dss_with_3des_ede_cbc_sha         = 0x000D,
    dh_rsa_with_3des_ede_cbc_sha         = 0x0010,
    dhe_dss_with_3des_ede_cbc_sha        = 0x0013,
    dhe_rsa_with_3des_ede_cbc_sha        = 0x0016,
    dh_dss_with_aes_128_cbc_sha          = 0x0030,
    dh_rsa_with_aes_128_cbc_sha          = 0x0031,
    dhe_dss_with_aes_128_cbc_sha         = 0x0032,
    dhe_rsa_with_aes_128_cbc_sha         = 0x0033,
    dh_dss_with_aes_256_cbc_sha          = 0x0036,
    dh_rsa_with_aes_256_cbc_sha          = 0x0037,
    dhe_dss_with_aes_256_cbc_sha         = 0x0038,
    dhe_rsa_with_aes_256_cbc_sha         = 0x0039,
    dh_dss_with_aes_128_cbc_sha256       = 0x003E,
    dh_rsa_with_aes_128_cbc_sha256       = 0x003F,
    dhe_dss_with_aes_128_cbc_sha256      = 0x0040,
    dhe_rsa_with_aes_128_cbc_sha256      = 0x0067,
    dh_dss_with_aes_256_cbc_sha256       = 0x0068,
    dh_rsa_with_aes_256_cbc_sha256       = 0x0069,
    dhe_dss_with_aes_256_cbc_sha256      = 0x006A,
    dhe_rsa_with_aes_256_cbc_sha256      = 0x006B,

    dh_anon_with_rc4_128_md5             = 0x0018,
    dh_anon_with_3des_ede_cbc_sha        = 0x001B,
    dh_anon_with_aes_128_cbc_sha         = 0x0034,
    dh_anon_with_aes_256_cbc_sha         = 0x003A,
    dh_anon_with_aes_128_cbc_sha256      = 0x006C,
    dh_anon_with_aes_256_cbc_sha256      = 0x006D,

    // http://tools.ietf.org/html/rfc5288
    rsa_with_aes_128_gcm_sha256          = 0x009C,
    rsa_with_aes_256_gcm_sha384          = 0x009D,
    dhe_rsa_with_aes_128_gcm_sha256      = 0x009E,
    dhe_rsa_with_aes_256_gcm_sha384      = 0x009F,
    dh_rsa_with_aes_128_gcm_sha256       = 0x00A0,
    dh_rsa_with_aes_256_gcm_sha384       = 0x00A1,
    dhe_dss_with_aes_128_gcm_sha256      = 0x00A2,
    dhe_dss_with_aes_256_gcm_sha384      = 0x00A3,
    dh_dss_with_aes_128_gcm_sha256       = 0x00A4,
    dh_dss_with_aes_256_gcm_sha384       = 0x00A5,
    dh_anon_with_aes_128_gcm_sha256      = 0x00A6,
    dh_anon_with_aes_256_gcm_sha384      = 0x00A7,

    // https://tools.ietf.org/html/rfc4492
    ecdh_ecdsa_with_null_sha             = 0xC001,
    ecdh_ecdsa_with_rc4_128_sha          = 0xC002,
    ecdh_ecdsa_with_3des_ede_cbc_sha     = 0xC003,
    ecdh_ecdsa_with_aes_128_cbc_sha      = 0xC004,
    ecdh_ecdsa_with_aes_256_cbc_sha      = 0xC005,

    ecdhe_ecdsa_with_null_sha            = 0xC006,
    ecdhe_ecdsa_with_rc4_128_sha         = 0xC007,
    ecdhe_ecdsa_with_3des_ede_cbc_sha    = 0xC008,
    ecdhe_ecdsa_with_aes_128_cbc_sha     = 0xC009,
    ecdhe_ecdsa_with_aes_256_cbc_sha     = 0xC00A,

    ecdh_rsa_with_null_sha               = 0xC00B,
    ecdh_rsa_with_rc4_128_sha            = 0xC00C,
    ecdh_rsa_with_3des_ede_cbc_sha       = 0xC00D,
    ecdh_rsa_with_aes_128_cbc_sha        = 0xC00E,
    ecdh_rsa_with_aes_256_cbc_sha        = 0xC00F,

    ecdhe_rsa_with_null_sha              = 0xC010,
    ecdhe_rsa_with_rc4_128_sha           = 0xC011,
    ecdhe_rsa_with_3des_ede_cbc_sha      = 0xC012,
    ecdhe_rsa_with_aes_128_cbc_sha       = 0xC013,
    ecdhe_rsa_with_aes_256_cbc_sha       = 0xC014,

    ecdh_anon_with_null_sha              = 0xC015,
    ecdh_anon_with_rc4_128_sha           = 0xC016,
    ecdh_anon_with_3des_ede_cbc_sha      = 0xC017,
    ecdh_anon_with_aes_128_cbc_sha       = 0xC018,
    ecdh_anon_with_aes_256_cbc_sha       = 0xC019,

    // https://tools.ietf.org/html/rfc5289
    ecdhe_ecdsa_with_aes_128_cbc_sha256  = 0xC023,
    ecdhe_ecdsa_with_aes_256_cbc_sha384  = 0xC024,
    ecdh_ecdsa_with_aes_128_cbc_sha256   = 0xC025,
    ecdh_ecdsa_with_aes_256_cbc_sha384   = 0xC026,
    ecdhe_rsa_with_aes_128_cbc_sha256    = 0xC027,
    ecdhe_rsa_with_aes_256_cbc_sha384    = 0xC028,
    ecdh_rsa_with_aes_128_cbc_sha256     = 0xC029,
    ecdh_rsa_with_aes_256_cbc_sha384     = 0xC02A,
    ecdhe_ecdsa_with_aes_128_gcm_sha256  = 0xC02B,
    ecdhe_ecdsa_with_aes_256_gcm_sha384  = 0xC02C,
    ecdh_ecdsa_with_aes_128_gcm_sha256   = 0xC02D,
    ecdh_ecdsa_with_aes_256_gcm_sha384   = 0xC02E,
    ecdhe_rsa_with_aes_128_gcm_sha256    = 0xC02F,
    ecdhe_rsa_with_aes_256_gcm_sha384    = 0xC030,
    ecdh_rsa_with_aes_128_gcm_sha256     = 0xC031,
    ecdh_rsa_with_aes_256_gcm_sha384     = 0xC032,

    // Experimental:
    ecdhe_rsa_with_chacha20_poly1305_sha256 = 0xCC13,
};

enum class key_exchange_algorithm {
    null,
    dhe_dss,
    dhe_rsa,
    dh_anon,
    rsa,
    dh_dss,
    dh_rsa,
    ecdh_ecdsa,
    ecdhe_ecdsa,
    ecdh_rsa,
    ecdhe_rsa,
    ecdh_anon,
};

inline bool is_ecc(key_exchange_algorithm kea) {
    return kea == key_exchange_algorithm::ecdh_ecdsa  ||
           kea == key_exchange_algorithm::ecdhe_ecdsa ||
           kea == key_exchange_algorithm::ecdh_rsa    ||
           kea == key_exchange_algorithm::ecdhe_rsa   ||
           kea == key_exchange_algorithm::ecdh_anon;
}

enum class prf_algorithm {
    sha256,
    sha384
};

enum class bulk_cipher_algorithm {
    null,
    rc4,
    _3des,
    aes_cbc,
    aes_gcm,
    chacha20,
};

enum class cipher_type {
    stream,
    block,
    aead
};

enum class mac_algorithm {
    null,
    hmac_md5,
    hmac_sha1,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512
};

// TODO: This isn't as clever as I hoped it would be
//       Of course some of the uglyness could be hidden
//       behind macros, but rethink before doing that

template<cipher_suite suite>
struct cipher_suite_traits;

namespace detail {

struct null_bulk_algo_traits {
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::null;
    static constexpr auto cipher_type            = tls::cipher_type::stream;
    static constexpr uint8_t key_length          = 0;
    static constexpr uint8_t block_length        = 0; // N/A
    static constexpr uint8_t fixed_iv_length     = 0;
    static constexpr uint8_t record_iv_length    = 0;
};

struct rc4_traits {
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::rc4;
    static constexpr auto cipher_type            = tls::cipher_type::stream;
    static constexpr uint8_t key_length          = 128/8;
    static constexpr uint8_t block_length        = 0; // N/A
    static constexpr uint8_t fixed_iv_length     = 0;
    static constexpr uint8_t record_iv_length    = 0;
};

struct _3des_traits {
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::_3des;
    static constexpr auto cipher_type            = tls::cipher_type::block;
    static constexpr uint8_t key_length          = 192/8;
    static constexpr uint8_t block_length        = 64/8;
    static constexpr uint8_t fixed_iv_length     = 0;
    static constexpr uint8_t record_iv_length    = 64/8;
};

template<unsigned aes_key_length_bits>
struct aes_cbc_traits {
    static_assert(aes_key_length_bits == 128 || aes_key_length_bits == 192 || aes_key_length_bits == 256, "Invalid AES key length");
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::aes_cbc;
    static constexpr auto cipher_type            = tls::cipher_type::block;
    static constexpr uint8_t key_length          = aes_key_length_bits / 8;
    static constexpr uint8_t block_length        = 128/8;
    static constexpr uint8_t fixed_iv_length     = 0;
    static constexpr uint8_t record_iv_length    = 128/8;
};

template<unsigned aes_key_length_bits>
struct aes_gcm_traits {
    static_assert(aes_key_length_bits == 128 || aes_key_length_bits == 192 || aes_key_length_bits == 256, "Invalid AES key length");
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::aes_gcm;
    static constexpr auto cipher_type            = tls::cipher_type::aead;
    static constexpr uint8_t key_length          = aes_key_length_bits / 8;
    static constexpr uint8_t block_length        = 128/8;
    static constexpr uint8_t fixed_iv_length     = 4;
    static constexpr uint8_t record_iv_length    = 8;
};

struct chacha20_poly1305_traits {
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::chacha20;
    static constexpr auto cipher_type            = tls::cipher_type::aead;
    static constexpr uint8_t key_length          = 256/8;
    static constexpr uint8_t block_length        = 64;
    static constexpr uint8_t fixed_iv_length     = 4;
    static constexpr uint8_t record_iv_length    = 0;
};

struct null_mac_algo_triats {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::null;
    static constexpr uint8_t mac_length          = 0;
    static constexpr uint8_t mac_key_length      = 0;
    static constexpr auto prf_algorithm          = tls::prf_algorithm::sha256;
};

struct hmac_md5_algo_traits {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::hmac_md5;
    static constexpr uint8_t mac_length          = 128/8;
    static constexpr uint8_t mac_key_length      = 128/8;
    static constexpr auto prf_algorithm          = tls::prf_algorithm::sha256;
};

struct hmac_sha_algo_traits {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::hmac_sha1;
    static constexpr uint8_t mac_length          = 160/8;
    static constexpr uint8_t mac_key_length      = 160/8;
    static constexpr auto prf_algorithm          = tls::prf_algorithm::sha256;
};

template<uint8_t mcl = 256/8>
struct hmac_sha256_algo_traits {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::hmac_sha256;
    static constexpr uint8_t mac_length          = 256/8;
    static constexpr uint8_t mac_key_length      = mcl;
    static constexpr auto prf_algorithm          = tls::prf_algorithm::sha256;
};

template<uint8_t mcl = 384/8>
struct hmac_sha384_algo_traits {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::hmac_sha384;
    static constexpr uint8_t mac_length          = 384/8;
    static constexpr uint8_t mac_key_length      = mcl;
    static constexpr auto prf_algorithm          = tls::prf_algorithm::sha384;
};

template<cipher_suite suite, key_exchange_algorithm key_exchange_algo, typename bulk_cipher_algo_traits, typename mac_algo_traits>
struct cipher_suite_traits_base {
    static constexpr auto cipher_suite           = suite;
    static constexpr auto key_exchange_algorithm = key_exchange_algo;
    static constexpr auto prf_algorithm          = mac_algo_traits::prf_algorithm;
    static constexpr auto bulk_cipher_algorithm  = bulk_cipher_algo_traits::bulk_cipher_algorithm;
    static constexpr auto cipher_type            = bulk_cipher_algo_traits::cipher_type;
    static constexpr uint8_t key_length          = bulk_cipher_algo_traits::key_length;
    static constexpr uint8_t block_length        = bulk_cipher_algo_traits::block_length;
    static constexpr uint8_t fixed_iv_length     = bulk_cipher_algo_traits::fixed_iv_length;
    static constexpr uint8_t record_iv_length    = bulk_cipher_algo_traits::record_iv_length;
    static constexpr auto mac_algorithm          = mac_algo_traits::mac_algorithm;
    static constexpr uint8_t mac_length          = mac_algo_traits::mac_length;
    static constexpr uint8_t mac_key_length      = mac_algo_traits::mac_key_length;
};

} // namespace detail

#define CS_TRAITS_SPEC(n, kex, bulk, mac)        \
template<>                                       \
struct cipher_suite_traits<cipher_suite::n>      \
    : public detail::cipher_suite_traits_base<   \
        cipher_suite::n,                         \
        key_exchange_algorithm::kex,             \
        detail::bulk,                            \
        detail::mac> {}

CS_TRAITS_SPEC(null_with_null_null, null, null_bulk_algo_traits, null_mac_algo_triats);
CS_TRAITS_SPEC(rsa_with_rc4_128_md5, rsa, rc4_traits, hmac_md5_algo_traits);
CS_TRAITS_SPEC(rsa_with_rc4_128_sha, rsa, rc4_traits, hmac_sha_algo_traits);
CS_TRAITS_SPEC(rsa_with_3des_ede_cbc_sha, rsa, _3des_traits, hmac_sha_algo_traits);
CS_TRAITS_SPEC(rsa_with_aes_128_cbc_sha, rsa, aes_cbc_traits<128>, hmac_sha_algo_traits);
CS_TRAITS_SPEC(rsa_with_aes_256_cbc_sha, rsa, aes_cbc_traits<256>, hmac_sha_algo_traits);
CS_TRAITS_SPEC(rsa_with_aes_128_cbc_sha256, rsa, aes_cbc_traits<128>, hmac_sha256_algo_traits<>);
CS_TRAITS_SPEC(rsa_with_aes_256_cbc_sha256, rsa, aes_cbc_traits<256>, hmac_sha256_algo_traits<>);
CS_TRAITS_SPEC(dhe_rsa_with_3des_ede_cbc_sha, dhe_rsa, _3des_traits, hmac_sha_algo_traits);
CS_TRAITS_SPEC(dhe_rsa_with_aes_128_cbc_sha, dhe_rsa, aes_cbc_traits<128>, hmac_sha_algo_traits);
CS_TRAITS_SPEC(dhe_rsa_with_aes_256_cbc_sha, dhe_rsa, aes_cbc_traits<256>, hmac_sha_algo_traits);
CS_TRAITS_SPEC(dhe_rsa_with_aes_128_cbc_sha256, dhe_rsa, aes_cbc_traits<128>, hmac_sha256_algo_traits<>);
CS_TRAITS_SPEC(dhe_rsa_with_aes_256_cbc_sha256, dhe_rsa, aes_cbc_traits<256>, hmac_sha256_algo_traits<>);
CS_TRAITS_SPEC(rsa_with_aes_128_gcm_sha256, rsa, aes_gcm_traits<128>, hmac_sha256_algo_traits<0>);
CS_TRAITS_SPEC(rsa_with_aes_256_gcm_sha384, rsa, aes_gcm_traits<256>, hmac_sha384_algo_traits<0>);
CS_TRAITS_SPEC(ecdhe_ecdsa_with_aes_128_cbc_sha, ecdhe_ecdsa, aes_cbc_traits<128>, hmac_sha_algo_traits);
CS_TRAITS_SPEC(ecdhe_ecdsa_with_aes_256_cbc_sha, ecdhe_ecdsa, aes_cbc_traits<256>, hmac_sha_algo_traits);
CS_TRAITS_SPEC(ecdhe_rsa_with_aes_128_cbc_sha, ecdhe_rsa, aes_cbc_traits<128>, hmac_sha_algo_traits);
CS_TRAITS_SPEC(ecdhe_rsa_with_aes_256_cbc_sha, ecdhe_rsa, aes_cbc_traits<256>, hmac_sha_algo_traits);
CS_TRAITS_SPEC(ecdhe_ecdsa_with_aes_128_gcm_sha256, ecdhe_ecdsa, aes_gcm_traits<128>, hmac_sha256_algo_traits<0>);
CS_TRAITS_SPEC(ecdhe_ecdsa_with_aes_256_gcm_sha384, ecdhe_ecdsa, aes_gcm_traits<256>, hmac_sha384_algo_traits<0>);
CS_TRAITS_SPEC(ecdhe_rsa_with_aes_128_gcm_sha256, ecdhe_rsa, aes_gcm_traits<128>, hmac_sha256_algo_traits<0>);
CS_TRAITS_SPEC(ecdhe_rsa_with_aes_256_gcm_sha384, ecdhe_rsa, aes_gcm_traits<256>, hmac_sha384_algo_traits<0>);
CS_TRAITS_SPEC(ecdhe_rsa_with_chacha20_poly1305_sha256, ecdhe_rsa, chacha20_poly1305_traits, hmac_sha256_algo_traits<0>);

#undef CS_TRAITS_SPEC

struct cipher_suite_parameters {
    const tls::cipher_suite           cipher_suite;
    const tls::key_exchange_algorithm key_exchange_algorithm;
    const tls::prf_algorithm          prf_algorithm;
    const tls::bulk_cipher_algorithm  bulk_cipher_algorithm;
    const tls::cipher_type            cipher_type;
    const uint8_t                     key_length;
    const uint8_t                     block_length;
    const uint8_t                     fixed_iv_length;
    const uint8_t                     record_iv_length;
    const tls::mac_algorithm          mac_algorithm;
    const uint8_t                     mac_length;
    const uint8_t                     mac_key_length;
};

enum class hash_algorithm : uint8_t;
hash_algorithm hash_algorithm_from_oid(const asn1::object_id& oid);
asn1::object_id oid_from_hash_algorithm(hash_algorithm hash_algo);
hash::hash_algorithm get_hash(hash_algorithm algo);
hash::hash_algorithm get_hmac(mac_algorithm algo, const std::vector<uint8_t>& key);
bool is_supported(cipher_suite suite);
cipher_suite_parameters parameters_from_suite(cipher_suite suite);

std::ostream& operator<<(std::ostream& os, key_exchange_algorithm e);
std::ostream& operator<<(std::ostream& os, prf_algorithm e);
std::ostream& operator<<(std::ostream& os, bulk_cipher_algorithm e);
std::ostream& operator<<(std::ostream& os, cipher_type e);
std::ostream& operator<<(std::ostream& os, mac_algorithm e);
std::ostream& operator<<(std::ostream& os, cipher_suite suite);
std::istream& operator>>(std::istream& is, cipher_suite& suite);
std::ostream& operator<<(std::ostream& os, const cipher_suite_parameters& csp);

class cipher_parameters {
public:
    enum operation { decrypt = 0, encrypt = 1 };

    cipher_parameters(operation op, const cipher_suite_parameters& suite_parameters, const std::vector<uint8_t>& mac_key, const std::vector<uint8_t>& enc_key, const std::vector<uint8_t>& fixed_iv);

    enum operation operation() const {
        return operation_;
    }

    hash::hash_algorithm hmac() const {
        assert(!mac_key().empty());
        return tls::get_hmac(suite_parameters_.mac_algorithm, mac_key());
    }

    const cipher_suite_parameters& suite_parameters() const {
        return suite_parameters_;
    }

    const std::vector<uint8_t>& mac_key() const {
        return mac_key_;
    }

    const std::vector<uint8_t>& enc_key() const {
        return enc_key_;
    }

    const std::vector<uint8_t>& fixed_iv() const {
        return fixed_iv_;
    }

private:
    enum operation          operation_;
    cipher_suite_parameters suite_parameters_;
    std::vector<uint8_t>    mac_key_;
    std::vector<uint8_t>    enc_key_;
    std::vector<uint8_t>    fixed_iv_;
};

class cipher {
public:
    explicit cipher(const cipher_parameters& parameters) : parameters_(parameters) {}
    virtual ~cipher() {}

    //
    // Encrypt/Decrypt 'data'. 'verbuffer' must contain the concatenation of sequence_number, content_type, protocol_version and content_length
    // For decryption the content length cannot be known in advance (this is the case with block ciphers) and must thus be filled out before
    // use by the cipher
    //
    // For encryption a complete data block is returned (encrypted data + any record IV + authentication code)
    // For decryption the decrypted data is returned or an exception is thrown if authentication/decryption failed.
    //
    std::vector<uint8_t> process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) {
        assert(verbuffer.size() == 13);
        return do_process(data, verbuffer);
    }

protected:
    //
    // For now we won't allow others to access the cipher parameters. It can always be made public if necessary.
    //
    const cipher_parameters& parameters() const {
        return parameters_;
    }

private:
    cipher_parameters parameters_;

    virtual std::vector<uint8_t> do_process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) = 0;
};

static const cipher_parameters null_cipher_parameters_e{cipher_parameters::encrypt, tls::parameters_from_suite(tls::cipher_suite::null_with_null_null), {}, {}, {}};
static const cipher_parameters null_cipher_parameters_d{cipher_parameters::decrypt, tls::parameters_from_suite(tls::cipher_suite::null_with_null_null), {}, {}, {}};

std::unique_ptr<cipher> make_cipher(const cipher_parameters& parameters);

} } // namespace funtls::tls

#endif
