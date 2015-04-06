#ifndef TLS_CIPHERS_H_INCLUDED
#define TLS_CIPHERS_H_INCLUDED

#include <iosfwd>
#include <cstdint>
#include <hash/hash.h>

namespace funtls { namespace tls {

enum class cipher_suite : uint16_t {
    null_with_null_null             = 0x0000,

    rsa_with_null_md5               = 0x0001,
    rsa_with_null_sha               = 0x0002,
    rsa_with_null_sha256            = 0x003B,
    rsa_with_rc4_128_md5            = 0x0004,
    rsa_with_rc4_128_sha            = 0x0005,
    rsa_with_3des_ede_cbc_sha       = 0x000A,
    rsa_with_aes_128_cbc_sha        = 0x002F,
    rsa_with_aes_256_cbc_sha        = 0x0035,
    rsa_with_aes_128_cbc_sha256     = 0x003C,
    rsa_with_aes_256_cbc_sha256     = 0x003D,

    dh_dss_with_3des_ede_cbc_sha    = 0x000D,
    dh_rsa_with_3des_ede_cbc_sha    = 0x0010,
    dhe_dss_with_3des_ede_cbc_sha   = 0x0013,
    dhe_rsa_with_3des_ede_cbc_sha   = 0x0016,
    dh_dss_with_aes_128_cbc_sha     = 0x0030,
    dh_rsa_with_aes_128_cbc_sha     = 0x0031,
    dhe_dss_with_aes_128_cbc_sha    = 0x0032,
    dhe_rsa_with_aes_128_cbc_sha    = 0x0033,
    dh_dss_with_aes_256_cbc_sha     = 0x0036,
    dh_rsa_with_aes_256_cbc_sha     = 0x0037,
    dhe_dss_with_aes_256_cbc_sha    = 0x0038,
    dhe_rsa_with_aes_256_cbc_sha    = 0x0039,
    dh_dss_with_aes_128_cbc_sha256  = 0x003E,
    dh_rsa_with_aes_128_cbc_sha256  = 0x003F,
    dhe_dss_with_aes_128_cbc_sha256 = 0x0040,
    dhe_rsa_with_aes_128_cbc_sha256 = 0x0067,
    dh_dss_with_aes_256_cbc_sha256  = 0x0068,
    dh_rsa_with_aes_256_cbc_sha256  = 0x0069,
    dhe_dss_with_aes_256_cbc_sha256 = 0x006A,
    dhe_rsa_with_aes_256_cbc_sha256 = 0x006B,

    dh_anon_with_rc4_128_md5        = 0x0018,
    dh_anon_with_3des_ede_cbc_sha   = 0x001B,
    dh_anon_with_aes_128_cbc_sha    = 0x0034,
    dh_anon_with_aes_256_cbc_sha    = 0x003A,
    dh_anon_with_aes_128_cbc_sha256 = 0x006C,
    dh_anon_with_aes_256_cbc_sha256 = 0x006D,
};

enum class key_exchange_algorithm {
    null,
    dhe_dss,
    dhe_rsa,
    dh_anon,
    rsa,
    dh_dss,
    dh_rsa
};

enum class prf_algorithm {
    tls_prf_sha256
};

enum class bulk_cipher_algorithm {
    null,
    rc4,
    _3des,
    aes
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

struct null_bulk_algo_traits {
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::null;
    static constexpr auto cipher_type            = tls::cipher_type::stream;
    static constexpr uint8_t key_length          = 0;
    static constexpr uint8_t block_length        = 0; // N/A
    static constexpr uint8_t iv_length           = 0;
};

struct rc4_traits {
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::rc4;
    static constexpr auto cipher_type            = tls::cipher_type::stream;
    static constexpr uint8_t key_length          = 128/8;
    static constexpr uint8_t block_length        = 0; // N/A
    static constexpr uint8_t iv_length           = 0;
};

struct _3des_traits {
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::_3des;
    static constexpr auto cipher_type            = tls::cipher_type::block;
    static constexpr uint8_t key_length          = 192/8;
    static constexpr uint8_t block_length        = 64/8;
    static constexpr uint8_t iv_length           = 64/8;
};

template<unsigned aes_key_length_bits>
struct aes_traits {
    static_assert(aes_key_length_bits == 128 || aes_key_length_bits == 192 || aes_key_length_bits == 256, "Invalid AES key length");
    static constexpr auto bulk_cipher_algorithm  = tls::bulk_cipher_algorithm::aes;
    static constexpr auto cipher_type            = tls::cipher_type::block;
    static constexpr uint8_t key_length          = aes_key_length_bits / 8;
    static constexpr uint8_t block_length        = 128/8;
    static constexpr uint8_t iv_length           = 128/8;
};

struct null_mac_algo_triats {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::null;
    static constexpr uint8_t mac_length          = 0;
    static constexpr uint8_t mac_key_length      = 0;
};

struct hmac_md5_algo_traits {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::hmac_md5;
    static constexpr uint8_t mac_length          = 128/8;
    static constexpr uint8_t mac_key_length      = 128/8;
};

struct hmac_sha_algo_traits {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::hmac_sha1;
    static constexpr uint8_t mac_length          = 160/8;
    static constexpr uint8_t mac_key_length      = 160/8;
};

struct hmac_sha256_algo_traits {
    static constexpr auto mac_algorithm          = tls::mac_algorithm::hmac_sha256;
    static constexpr uint8_t mac_length          = 256/8;
    static constexpr uint8_t mac_key_length      = 256/8;
};

namespace detail {

template<cipher_suite suite, key_exchange_algorithm key_exchange_algo, typename bulk_cipher_algo_traits, typename mac_algo_traits>
struct cipher_suite_traits_base {
    static constexpr auto cipher_suite           = suite;
    static constexpr auto key_exchange_algorithm = key_exchange_algo;
    static constexpr auto prf_algorithm          = tls::prf_algorithm::tls_prf_sha256;
    static constexpr auto bulk_cipher_algorithm  = bulk_cipher_algo_traits::bulk_cipher_algorithm;
    static constexpr auto cipher_type            = bulk_cipher_algo_traits::cipher_type;
    static constexpr uint8_t key_length          = bulk_cipher_algo_traits::key_length;
    static constexpr uint8_t block_length        = bulk_cipher_algo_traits::block_length;
    static constexpr uint8_t iv_length           = bulk_cipher_algo_traits::iv_length;
    static constexpr auto mac_algorithm          = mac_algo_traits::mac_algorithm;
    static constexpr uint8_t mac_length          = mac_algo_traits::mac_length;
    static constexpr uint8_t mac_key_length      = mac_algo_traits::mac_key_length;
};

} // namespace detail

template<>
struct cipher_suite_traits<cipher_suite::null_with_null_null>
    : public detail::cipher_suite_traits_base<
        cipher_suite::null_with_null_null,
        key_exchange_algorithm::null,
        null_bulk_algo_traits,
        null_mac_algo_triats> {
};

template<>
struct cipher_suite_traits<cipher_suite::rsa_with_rc4_128_md5>
    : public detail::cipher_suite_traits_base<
        cipher_suite::rsa_with_rc4_128_sha,
        key_exchange_algorithm::rsa,
        rc4_traits,
        hmac_md5_algo_traits> {
};

template<>
struct cipher_suite_traits<cipher_suite::rsa_with_rc4_128_sha>
    : public detail::cipher_suite_traits_base<
        cipher_suite::rsa_with_rc4_128_sha,
        key_exchange_algorithm::rsa,
        rc4_traits,
        hmac_sha_algo_traits> {
};

template<>
struct cipher_suite_traits<cipher_suite::rsa_with_3des_ede_cbc_sha>
    : public detail::cipher_suite_traits_base<
        cipher_suite::rsa_with_3des_ede_cbc_sha,
        key_exchange_algorithm::rsa,
        _3des_traits,
        hmac_sha_algo_traits> {
};

template<>
struct cipher_suite_traits<cipher_suite::rsa_with_aes_128_cbc_sha>
    : public detail::cipher_suite_traits_base<
        cipher_suite::rsa_with_aes_128_cbc_sha,
        key_exchange_algorithm::rsa,
        aes_traits<128>,
        hmac_sha_algo_traits> {
};

template<>
struct cipher_suite_traits<cipher_suite::rsa_with_aes_256_cbc_sha>
    : public detail::cipher_suite_traits_base<
        cipher_suite::rsa_with_aes_128_cbc_sha,
        key_exchange_algorithm::rsa,
        aes_traits<256>,
        hmac_sha_algo_traits> {
};


template<>
struct cipher_suite_traits<cipher_suite::rsa_with_aes_128_cbc_sha256>
    : public detail::cipher_suite_traits_base<
        cipher_suite::rsa_with_aes_128_cbc_sha256,
        key_exchange_algorithm::rsa,
        aes_traits<128>,
        hmac_sha256_algo_traits> {
};

template<>
struct cipher_suite_traits<cipher_suite::rsa_with_aes_256_cbc_sha256>
    : public detail::cipher_suite_traits_base<
        cipher_suite::rsa_with_aes_256_cbc_sha256,
        key_exchange_algorithm::rsa,
        aes_traits<256>,
        hmac_sha256_algo_traits> {
};

template<>
struct cipher_suite_traits<cipher_suite::dh_rsa_with_3des_ede_cbc_sha>
    : public detail::cipher_suite_traits_base<
        cipher_suite::dh_rsa_with_3des_ede_cbc_sha,
        key_exchange_algorithm::dh_rsa,
        _3des_traits,
        hmac_sha_algo_traits> {
};

template<>
struct cipher_suite_traits<cipher_suite::dhe_rsa_with_3des_ede_cbc_sha>
    : public detail::cipher_suite_traits_base<
        cipher_suite::dhe_rsa_with_3des_ede_cbc_sha,
        key_exchange_algorithm::dhe_rsa,
        _3des_traits,
        hmac_sha_algo_traits> {
};

template<>
struct cipher_suite_traits<cipher_suite::dh_rsa_with_aes_128_cbc_sha>
    : public detail::cipher_suite_traits_base<
        cipher_suite::dh_rsa_with_3des_ede_cbc_sha,
        key_exchange_algorithm::dh_rsa,
        aes_traits<128>,
        hmac_sha_algo_traits> {
};

struct cipher_suite_parameters {
    const tls::cipher_suite           cipher_suite;
    const tls::key_exchange_algorithm key_exchange_algorithm;
    const tls::prf_algorithm          prf_algorithm;
    const tls::bulk_cipher_algorithm  bulk_cipher_algorithm;
    const tls::cipher_type            cipher_type;
    const uint8_t                     key_length;
    const uint8_t                     block_length;
    const uint8_t                     iv_length;
    const tls::mac_algorithm          mac_algorithm;
    const uint8_t                     mac_length;
    const uint8_t                     mac_key_length;
};

hash::hash_algorithm get_hmac(mac_algorithm algo, const std::vector<uint8_t>& key);
cipher_suite_parameters parameters_from_suite(cipher_suite suite);

std::ostream& operator<<(std::ostream& os, key_exchange_algorithm e);
std::ostream& operator<<(std::ostream& os, prf_algorithm e);
std::ostream& operator<<(std::ostream& os, bulk_cipher_algorithm e);
std::ostream& operator<<(std::ostream& os, cipher_type e);
std::ostream& operator<<(std::ostream& os, mac_algorithm e);
std::ostream& operator<<(std::ostream& os, cipher_suite suite);
std::ostream& operator<<(std::ostream& os, const cipher_suite_parameters& csp);

} } // namespace funtls::tls

#endif
