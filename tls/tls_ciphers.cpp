#include "tls_ciphers.h"
#include <util/base_conversion.h>
#include <util/test.h>
#include <ostream>
#include <cassert>

namespace {

std::string cipher_suite_hex(funtls::tls::cipher_suite suite)
{
    const uint8_t b[2] = { static_cast<uint8_t>(static_cast<uint16_t>(suite) >> 8), static_cast<uint8_t>(static_cast<uint16_t>(suite)) };
    return funtls::util::base16_encode(b, sizeof(b));
}

template<funtls::tls::cipher_suite suite>
funtls::tls::cipher_suite_parameters from_suite_impl()
{
    using t = funtls::tls::cipher_suite_traits<suite>;
    return {
        t::cipher_suite,
        t::key_exchange_algorithm,
        t::prf_algorithm,
        t::bulk_cipher_algorithm,
        t::cipher_type,
        t::key_length,
        t::block_length,
        t::iv_length,
        t::mac_algorithm,
        t::mac_length,
        t::mac_key_length
    };
}

bool try_consume(std::string& in, const std::string& t)
{
    if (in.substr(0, t.size()) == t) {
        in = in.substr(t.size());
        return true;
    }
    return false;
}

} // unnamed namespace

namespace funtls { namespace tls {

hash::hash_algorithm get_hmac(mac_algorithm algo, const std::vector<uint8_t>& key)
{
    switch (algo) {
    case mac_algorithm::null:        break;
    case mac_algorithm::hmac_md5:    return hash::hmac_md5{key};
    case mac_algorithm::hmac_sha1:   return hash::hmac_sha1{key};
    case mac_algorithm::hmac_sha256: return hash::hmac_sha256{key};
    case mac_algorithm::hmac_sha384: return hash::hmac_sha384{key};
    case mac_algorithm::hmac_sha512: return hash::hmac_sha512{key};
    }
    assert(false);
    FUNTLS_CHECK_FAILURE("Unimplemented MAC algorithm " + std::to_string((int)algo));
}

std::ostream& operator<<(std::ostream& os, key_exchange_algorithm e)
{
    switch (e) {
    case key_exchange_algorithm::null:    return os << "NULL";
    case key_exchange_algorithm::dhe_dss: return os << "DHE_DSS";
    case key_exchange_algorithm::dhe_rsa: return os << "DHE_RSA";
    case key_exchange_algorithm::dh_anon: return os << "DH_anon";
    case key_exchange_algorithm::rsa:     return os << "RSA";
    case key_exchange_algorithm::dh_dss:  return os << "DH_DSS";
    case key_exchange_algorithm::dh_rsa:  return os << "DH_RSA";
    }
    assert(false);
    return os << "Unknown TLS key exchange algorithm " << static_cast<unsigned>(e);
}

std::ostream& operator<<(std::ostream& os, prf_algorithm e)
{
    switch (e) {
    case prf_algorithm::tls_prf_sha256: return os << "TLS_PRF_SHA256";
    }
    assert(false);
    return os << "Unknown TLS PRF algorithm " << static_cast<unsigned>(e);
}

std::ostream& operator<<(std::ostream& os, bulk_cipher_algorithm e)
{
    switch (e) {
    case bulk_cipher_algorithm::null:  return os << "NULL";
    case bulk_cipher_algorithm::rc4:   return os << "RC4";
    case bulk_cipher_algorithm::_3des: return os << "3DES";
    case bulk_cipher_algorithm::aes:   return os << "AES";
    }
    assert(false);
    return os << "Unknown TLS bulk cipher algorithm " << static_cast<unsigned>(e);
}

std::ostream& operator<<(std::ostream& os, cipher_type e)
{
    switch (e) {
    case cipher_type::stream: return os << "stream";
    case cipher_type::block:  return os << "block";
    case cipher_type::aead:   return os << "AEAD";
    }
    assert(false);
    return os << "Unknown TLS cipher type " << static_cast<unsigned>(e);
}

std::ostream& operator<<(std::ostream& os, mac_algorithm e)
{
    switch (e) {
    case mac_algorithm::null:        return os << "NULL";
    case mac_algorithm::hmac_md5:    return os << "MD5";
    case mac_algorithm::hmac_sha1:   return os << "SHA";
    case mac_algorithm::hmac_sha256: return os << "SHA256";
    case mac_algorithm::hmac_sha384: return os << "SHA384";
    case mac_algorithm::hmac_sha512: return os << "SHA512";
    }
    assert(false);
    return os << "Unknown TLS MAC algorithm " << static_cast<unsigned>(e);
}

#define ALL_SUPPORTED_SUITES(f) \
        f(null_with_null_null);\
        f(rsa_with_rc4_128_md5);\
        f(rsa_with_rc4_128_sha);\
        f(rsa_with_3des_ede_cbc_sha);\
        f(rsa_with_aes_128_cbc_sha);\
        f(rsa_with_aes_256_cbc_sha);\
        f(rsa_with_aes_128_cbc_sha256);\
        f(rsa_with_aes_256_cbc_sha256);\
        f(dhe_rsa_with_3des_ede_cbc_sha);\
        f(dhe_rsa_with_aes_128_cbc_sha);\
        f(dhe_rsa_with_aes_256_cbc_sha);\
        f(dhe_rsa_with_aes_128_cbc_sha256);\
        f(dhe_rsa_with_aes_256_cbc_sha256)


cipher_suite_parameters parameters_from_suite(cipher_suite suite)
{
    switch (suite) {
#define PARAMETERS_FROM_SUITE_CASE(cs) case cipher_suite::cs: return from_suite_impl<cipher_suite::cs>()
        ALL_SUPPORTED_SUITES(PARAMETERS_FROM_SUITE_CASE);
#undef PARAMETERS_FROM_SUITE_CASE
        default: // TODO: REMOVE
        break;
    }
    FUNTLS_CHECK_FAILURE("Unknown TLS cipher suite " + cipher_suite_hex(suite));
}

std::ostream& operator<<(std::ostream& os, cipher_suite suite)
{
    const auto csp = parameters_from_suite(suite);
    os << "TLS_" << csp.key_exchange_algorithm;
    os << "_WITH_" << csp.bulk_cipher_algorithm;
    if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::rc4) {
        os << "_" << 8*csp.key_length;
    } else if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::_3des) {
        os << "_EDE_CBC";
    } else if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::aes) {
        os << "_" << 8*csp.key_length << "_CBC";
    } else {
        assert(csp.bulk_cipher_algorithm == bulk_cipher_algorithm::null);
    }
    os << "_" << csp.mac_algorithm;
    return os;
}

std::istream& operator>>(std::istream& is, cipher_suite& suite)
{
    std::string text;
    if (!(is >> text)) {
        return is;
    }
    const auto saved_text = text;
    // Convert to lowercase and replace - with _
    for (auto& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c += 'a'-'A';
        } else if (c == '-') {
            c = '_';
        }
    }
    // skip (optional) TLS_ prefix
    (void) try_consume(text, "tls_");

    // Parse key exchange algorithm
    key_exchange_algorithm kex_algo = key_exchange_algorithm::rsa;
    if (try_consume(text, "rsa_")) {
    } else if (try_consume(text, "dhe_rsa_")) {
        kex_algo = key_exchange_algorithm::dhe_rsa;
    }

    // Skip (optional) with_
    (void) try_consume(text, "with_");

    // Parse bulk cipher algorithm
    bulk_cipher_algorithm cipher_algo = bulk_cipher_algorithm::null;
    unsigned bits = 0;
    if (try_consume(text, "rc4_128_") || try_consume(text, "rc4_")) {
        cipher_algo = bulk_cipher_algorithm::rc4;
        bits = 128;
    } else if (try_consume(text, "3des_ede_cbc_") || try_consume(text, "des_cbc3_")) {
        cipher_algo = bulk_cipher_algorithm::_3des;
        bits = 192;
    } else if (try_consume(text, "aes_128_cbc_") || try_consume(text, "aes128_")) {
        cipher_algo = bulk_cipher_algorithm::aes;
        bits = 128;
    } else if (try_consume(text, "aes_256_cbc_") || try_consume(text, "aes256_")) {
        cipher_algo = bulk_cipher_algorithm::aes;
        bits = 256;
    } else {
        FUNTLS_CHECK_FAILURE("Could not parse block cipher algorithm from " + saved_text);
    }
    FUNTLS_CHECK_BINARY(cipher_algo, !=, bulk_cipher_algorithm::null, "Invalid bulk cipher algorithm specified");

    // Parse MAC algorithm
    mac_algorithm mac_algo = mac_algorithm::null;
    if (try_consume(text, "sha256")) {
        mac_algo = mac_algorithm::hmac_sha256;
    } else if (try_consume(text, "sha")) {
        mac_algo = mac_algorithm::hmac_sha1;
    } else if (try_consume(text, "md5")) {
        mac_algo = mac_algorithm::hmac_md5;
    } else {
        FUNTLS_CHECK_FAILURE("Could not parse MAC algorithm from " + saved_text);
    }
    FUNTLS_CHECK_BINARY(mac_algo, !=, mac_algorithm::null, "Invalid MAC algorithm");

    FUNTLS_CHECK_BINARY(text.size(), ==, 0, "Unparsed found in cipher suite '" + saved_text + "'");

#define MATCH_SUITE(cs) do {\
    using t = cipher_suite_traits<cipher_suite::cs>;\
    if (kex_algo != t::key_exchange_algorithm) break;\
    if (cipher_algo != t::bulk_cipher_algorithm) break;\
    if (bits/8 != t::key_length) break;\
    if (mac_algo != t::mac_algorithm) break;\
    suite = cipher_suite::cs;\
    return is;\
} while(0)
    ALL_SUPPORTED_SUITES(MATCH_SUITE);
#undef MATCH_SUITE
    std::ostringstream oss;
    oss << "KEX=" << kex_algo << " Cipher=" << cipher_algo << " bits=" << bits << " MAC=" << mac_algo;
    FUNTLS_CHECK_FAILURE("Not implemented for " + oss.str());
    suite = cipher_suite::null_with_null_null;
    return is;
}

std::ostream& operator<<(std::ostream& os, const cipher_suite_parameters& csp)
{
    os << "cipher_suite           = 0x" << cipher_suite_hex(csp.cipher_suite) << " " << csp.cipher_suite << '\n';
    os << "key_exchange_algorithm = " << csp.key_exchange_algorithm << '\n';
    os << "prf_algorithm          = " << csp.prf_algorithm << '\n';
    os << "bulk_cipher_algorithm  = " << csp.bulk_cipher_algorithm << '\n';
    os << "cipher_type            = " << csp.cipher_type << '\n';
    os << "key_length             = " << static_cast<unsigned>(csp.key_length) << '\n';
    os << "block_length           = " << static_cast<unsigned>(csp.block_length) << '\n';
    os << "iv_length              = " << static_cast<unsigned>(csp.iv_length) << '\n';
    os << "mac_algorithm          = " << csp.mac_algorithm << '\n';
    os << "mac_length             = " << static_cast<unsigned>(csp.mac_length) << '\n';
    os << "mac_key_length         = " << static_cast<unsigned>(csp.mac_key_length) << ' ';
    return os;
}

} } // namespace funtls::tls
