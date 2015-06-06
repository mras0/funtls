#ifndef FUNTLS_EC_EC_H_INCLUDED
#define FUNTLS_EC_EC_H_INCLUDED

#include <iosfwd>
#include <vector>
#include <cassert>

#include <int_util/int.h>

namespace funtls { namespace ec {

using field_elem = large_uint;

struct point {
    field_elem x;
    field_elem y;
};

static const point infinity{424242, 424242}; // HACK, don't depend on the exact value

inline bool operator==(const point& lhs, const point& rhs) {
    return lhs.x == rhs.x && lhs.y == rhs.y;
}

inline bool operator!=(const point& lhs, const point& rhs) {
    return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& os, const point& p);

std::vector<uint8_t> point_to_bytes(const point& p, size_t size);
point point_from_bytes(const std::vector<uint8_t>& in);

// Note: generative primtive elliptic curves not supported
// Elliptic curve in GF(p) on the form y^2 = x^3 + ax + b'
struct curve {
    field_elem p; // field prime
    field_elem a; // curve 'a' parameter
    field_elem b; // curve 'b' parameter
    point G; // base point (Gx, Gy)
    field_elem n; // prime 'n' - order of base point
    int h; // co factor #E(F_p)/n

    void check() const;
    void check_public_key(const point& Q) const ;
    bool on_curve(const point& point) const;
    point add(const point& lhs, const point& rhs) const;
    point sqr(const point& point) const;
    point mul(field_elem m, point point) const;
    point mul(const point& point, const field_elem& m) const;
    void verify_ecdsa_signature(const point& Q, const field_elem& r, const field_elem& s, const field_elem& e) const;
};

extern const curve secp256r1;
extern const curve secp384r1;

} } // namespace funtls::ec

#endif

