#include <tls/tls_ecc.h>
#include <tls/tls_ser.h>
#include <util/test.h>
#include <util/base_conversion.h>
#include <int_util/int_util.h>
#include <ec/ec.h>

namespace funtls { namespace tls {

const ec::curve& curve_from_name(named_curve nc)
{
    if (nc == named_curve::secp256r1) return ec::secp256r1;
    if (nc == named_curve::secp384r1) return ec::secp384r1;
    std::ostringstream msg;
    msg << "Unsupported curve " << nc;
    FUNTLS_CHECK_FAILURE(msg.str());
}

std::ostream& operator<<(std::ostream& os, named_curve nc)
{
#define C(x) if (nc == named_curve::x) return os << #x
    C(sect163k1); C(sect163r1); C(sect163r2); C(sect193r1); C(sect193r2); C(sect233k1);
    C(sect233r1); C(sect239k1); C(sect283k1); C(sect283r1); C(sect409k1); C(sect409r1);
    C(sect571k1); C(sect571r1); C(secp160k1); C(secp160r1); C(secp160r2); C(secp192k1);
    C(secp192r1); C(secp224k1); C(secp224r1); C(secp256k1); C(secp256r1); C(secp384r1);
    C(secp521r1); C(arbitrary_explicit_prime_curves); C(arbitrary_explicit_char2_curves);
#undef C
    return os << "<named_curve " << (unsigned)nc << ">";
}

std::ostream& operator<<(std::ostream& os, ec_curve_type ct)
{
    switch (ct) {
        case ec_curve_type::explicit_prime : return os << "explicit_prime";
        case ec_curve_type::explicit_char2 : return os << "explicit_char2";
        case ec_curve_type::named_curve    : return os << "named_curve";
    }
    return os << "<ec_curve_type " << (unsigned)ct << ">";
}

void append_to_buffer(std::vector<uint8_t>& buffer, const ec_parameters& item) {
    FUNTLS_CHECK_BINARY(item.curve_type, ==, ec_curve_type::named_curve, "Unsupported curve type");
    append_to_buffer(buffer, item.curve_type);
    append_to_buffer(buffer, item.named_curve);
}

void from_bytes(elliptic_curves_extension& item, util::buffer_view& buffer) {
    from_bytes(item.elliptic_curve_list, buffer);
}

void append_to_buffer(std::vector<uint8_t>& buffer, const elliptic_curves_extension& item) {
    append_to_buffer(buffer, item.elliptic_curve_list);
}

std::ostream& operator<<(std::ostream& os, const elliptic_curves_extension& ext) {
    return os << ext.extension_type << " " << ext.elliptic_curve_list;
}

std::ostream& operator<<(std::ostream& os, ec_point_format pf) {
    switch (pf) {
    case ec_point_format::uncompressed: return os << "uncompressed";
    case ec_point_format::ansiX962_compressed_prime: return os << "ansiX962_compressed_prime";
    case ec_point_format::ansiX962_compressed_char2: return os << "ansiX962_compressed_char2";
    }
    assert(false);
    return os;
}

void from_bytes(ec_point_formats_extension& item, util::buffer_view& buffer) {
    from_bytes(item.ec_point_format_list, buffer);
}

void append_to_buffer(std::vector<uint8_t>& buffer, const ec_point_formats_extension& item) {
    append_to_buffer(buffer, item.ec_point_format_list);
}

std::ostream& operator<<(std::ostream& os, const ec_point_formats_extension& ext) {
    return os << ext.extension_type << " " << ext.ec_point_format_list;
}

void append_to_buffer(std::vector<uint8_t>& buffer, const server_ec_dh_params& item) {
    append_to_buffer(buffer, item.curve_params);
    append_to_buffer(buffer, item.public_key);
}

void append_to_buffer(std::vector<uint8_t>& buffer, const server_key_exchange_ec_dhe& item) {
    append_to_buffer(buffer, item.params);
    append_to_buffer(buffer, item.signature);
}

void append_to_buffer(std::vector<uint8_t>& buffer, const client_key_exchange_ecdhe_ecdsa& item) {
    append_to_buffer(buffer, item.ecdh_Yc);
}

void from_bytes(ec_parameters& item, util::buffer_view& buffer) {
    from_bytes(item.curve_type, buffer);
    FUNTLS_CHECK_BINARY(item.curve_type, ==, ec_curve_type::named_curve, "Unsupported curve type");
    from_bytes(item.named_curve, buffer);
}

void from_bytes(server_ec_dh_params& item, util::buffer_view& buffer) {
    from_bytes(item.curve_params, buffer);
    from_bytes(item.public_key, buffer);
}

void from_bytes(server_key_exchange_ec_dhe& item, util::buffer_view& buffer) {
    from_bytes(item.params, buffer);
    from_bytes(item.signature, buffer);
}

void from_bytes(client_key_exchange_ecdhe_ecdsa& item, util::buffer_view& buffer) {
    from_bytes(item.ecdh_Yc, buffer);
}

} } // namespace funtls::tls
