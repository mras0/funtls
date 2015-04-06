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

cipher_suite_parameters parameters_from_suite(cipher_suite suite)
{
    switch (suite) {
#define PARAMETERS_FROM_SUITE_CASE(cs) case cipher_suite::cs: return from_suite_impl<cipher_suite::cs>()
        PARAMETERS_FROM_SUITE_CASE(null_with_null_null);
        PARAMETERS_FROM_SUITE_CASE(rsa_with_rc4_128_md5);
        PARAMETERS_FROM_SUITE_CASE(rsa_with_rc4_128_sha);
        PARAMETERS_FROM_SUITE_CASE(rsa_with_3des_ede_cbc_sha);
        PARAMETERS_FROM_SUITE_CASE(rsa_with_aes_128_cbc_sha);
        PARAMETERS_FROM_SUITE_CASE(rsa_with_aes_256_cbc_sha);
        PARAMETERS_FROM_SUITE_CASE(rsa_with_aes_128_cbc_sha256);
        PARAMETERS_FROM_SUITE_CASE(rsa_with_aes_256_cbc_sha256);
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
    } else if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::_3des || csp.bulk_cipher_algorithm == bulk_cipher_algorithm::aes) {
        os << "_" << 8*csp.key_length << "_CBC";
    } else {
        assert(csp.bulk_cipher_algorithm == bulk_cipher_algorithm::null);
    }
    os << "_" << csp.mac_algorithm;
    return os;
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
