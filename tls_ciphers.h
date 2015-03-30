#ifndef TLS_CIPHERS_H_INCLUDED
#define TLS_CIPHERS_H_INCLUDED

#include "tls.h"

namespace tls {

constexpr cipher_suite null_with_null_null             = { { 0x00, 0x00 } };

constexpr cipher_suite rsa_with_null_md5               = { { 0x00, 0x01 } };
constexpr cipher_suite rsa_with_null_sha               = { { 0x00, 0x02 } };
constexpr cipher_suite rsa_with_null_sha256            = { { 0x00, 0x3B } };
constexpr cipher_suite rsa_with_rc4_128_md5            = { { 0x00, 0x04 } };
constexpr cipher_suite rsa_with_rc4_128_sha            = { { 0x00, 0x05 } };
constexpr cipher_suite rsa_with_3des_ede_cbc_sha       = { { 0x00, 0x0A } };
constexpr cipher_suite rsa_with_aes_128_cbc_sha        = { { 0x00, 0x2F } };
constexpr cipher_suite rsa_with_aes_256_cbc_sha        = { { 0x00, 0x35 } };
constexpr cipher_suite rsa_with_aes_128_cbc_sha256     = { { 0x00, 0x3C } };
constexpr cipher_suite rsa_with_aes_256_cbc_sha256     = { { 0x00, 0x3D } };

constexpr cipher_suite dh_dss_with_3des_ede_cbc_sha    = { { 0x00, 0x0D } };
constexpr cipher_suite dh_rsa_with_3des_ede_cbc_sha    = { { 0x00, 0x10 } };
constexpr cipher_suite dhe_dss_with_3des_ede_cbc_sha   = { { 0x00, 0x13 } };
constexpr cipher_suite dhe_rsa_with_3des_ede_cbc_sha   = { { 0x00, 0x16 } };
constexpr cipher_suite dh_dss_with_aes_128_cbc_sha     = { { 0x00, 0x30 } };
constexpr cipher_suite dh_rsa_with_aes_128_cbc_sha     = { { 0x00, 0x31 } };
constexpr cipher_suite dhe_dss_with_aes_128_cbc_sha    = { { 0x00, 0x32 } };
constexpr cipher_suite dhe_rsa_with_aes_128_cbc_sha    = { { 0x00, 0x33 } };
constexpr cipher_suite dh_dss_with_aes_256_cbc_sha     = { { 0x00, 0x36 } };
constexpr cipher_suite dh_rsa_with_aes_256_cbc_sha     = { { 0x00, 0x37 } };
constexpr cipher_suite dhe_dss_with_aes_256_cbc_sha    = { { 0x00, 0x38 } };
constexpr cipher_suite dhe_rsa_with_aes_256_cbc_sha    = { { 0x00, 0x39 } };
constexpr cipher_suite dh_dss_with_aes_128_cbc_sha256  = { { 0x00, 0x3E } };
constexpr cipher_suite dh_rsa_with_aes_128_cbc_sha256  = { { 0x00, 0x3F } };
constexpr cipher_suite dhe_dss_with_aes_128_cbc_sha256 = { { 0x00, 0x40 } };
constexpr cipher_suite dhe_rsa_with_aes_128_cbc_sha256 = { { 0x00, 0x67 } };
constexpr cipher_suite dh_dss_with_aes_256_cbc_sha256  = { { 0x00, 0x68 } };
constexpr cipher_suite dh_rsa_with_aes_256_cbc_sha256  = { { 0x00, 0x69 } };
constexpr cipher_suite dhe_dss_with_aes_256_cbc_sha256 = { { 0x00, 0x6A } };
constexpr cipher_suite dhe_rsa_with_aes_256_cbc_sha256 = { { 0x00, 0x6B } };

constexpr cipher_suite dh_anon_with_rc4_128_md5        = { { 0x00, 0x18 } };
constexpr cipher_suite dh_anon_with_3des_ede_cbc_sha   = { { 0x00, 0x1B } };
constexpr cipher_suite dh_anon_with_aes_128_cbc_sha    = { { 0x00, 0x34 } };
constexpr cipher_suite dh_anon_with_aes_256_cbc_sha    = { { 0x00, 0x3A } };
constexpr cipher_suite dh_anon_with_aes_128_cbc_sha256 = { { 0x00, 0x6C } };
constexpr cipher_suite dh_anon_with_aes_256_cbc_sha256 = { { 0x00, 0x6D } };

} // namespace tls

#endif
