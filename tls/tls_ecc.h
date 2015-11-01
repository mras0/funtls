#ifndef TLS_ECC_H_INCLUDED
#define TLS_ECC_H_INCLUDED

#include "tls.h"

// Forward declarations
namespace funtls {
    namespace ec { struct curve; }
    namespace util { struct buffer_view; }
}

namespace funtls { namespace tls {

// elliptic_curves extension
enum class named_curve : uint16 {
    sect163k1 = 1,
    sect163r1 = 2,
    sect163r2 = 3,
    sect193r1 = 4,
    sect193r2 = 5,
    sect233k1 = 6,
    sect233r1 = 7,
    sect239k1 = 8,
    sect283k1 = 9,
    sect283r1 = 10,
    sect409k1 = 11,
    sect409r1 = 12,
    sect571k1 = 13,
    sect571r1 = 14,
    secp160k1 = 15,
    secp160r1 = 16,
    secp160r2 = 17,
    secp192k1 = 18,
    secp192r1 = 19,
    secp224k1 = 20,
    secp224r1 = 21,
    secp256k1 = 22,
    secp256r1 = 23,
    secp384r1 = 24,
    secp521r1 = 25,
    arbitrary_explicit_prime_curves = 0xFF01,
    arbitrary_explicit_char2_curves = 0xFF02,
};

const ec::curve& curve_from_name(named_curve nc);

std::ostream& operator<<(std::ostream& os, named_curve nc);

using named_curves_list = vector<named_curve, 2, (1<<16)-2>;
extension make_named_curves(const named_curves_list& named_curves);

// ec_point_formats extension
enum class ec_point_format : uint8 {
    uncompressed = 0,
    ansiX962_compressed_prime = 1,
    ansiX962_compressed_char2 = 2
};
using ec_point_format_list = vector<ec_point_format, 1, (1<<8)-1>;

extension make_ec_point_formats(const ec_point_format_list& point_formats);

enum class ec_curve_type : uint8 {
    explicit_prime = 1,
    explicit_char2 = 2,
    named_curve    = 3,
};

std::ostream& operator<<(std::ostream& os, ec_curve_type ct);

using ec_point = vector<uint8, 1, (1<<8)-1>;
//struct ec_curve {
//    ec_point a;
//    ec_point b;
//};
// enum { ec_basis_trinomial, ec_basis_pentanomial } ECBasisType;

struct ec_parameters {
    ec_curve_type curve_type;
    union {
        tls::named_curve named_curve;
    };
};

void from_bytes(ec_parameters& item, util::buffer_view& buffer);
void append_to_buffer(std::vector<uint8_t>& buffer, const ec_parameters& item);

struct server_ec_dh_params {
    ec_parameters curve_params;
    ec_point      public_key;
};

void append_to_buffer(std::vector<uint8_t>& buffer, const server_ec_dh_params& item);
void from_bytes(server_ec_dh_params& item, util::buffer_view& buffer);

struct server_key_exchange_ec_dhe {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::server_key_exchange;

    server_ec_dh_params params;
    signed_signature    signature;
    // signature
};

void append_to_buffer(std::vector<uint8_t>& buffer, const server_key_exchange_ec_dhe& item);
void from_bytes(server_key_exchange_ec_dhe& item, util::buffer_view& buffer);

struct client_key_exchange_ecdhe_ecdsa {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::client_key_exchange;
    ec_point ecdh_Yc;
};

void append_to_buffer(std::vector<uint8_t>& buffer, const client_key_exchange_ecdhe_ecdsa& item);

} } // namespace funtls::tls

#endif
