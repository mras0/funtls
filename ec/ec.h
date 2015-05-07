#ifndef FUNTLS_EC_EC_H_INCLUDED
#define FUNTLS_EC_EC_H_INCLUDED

#include <iosfwd>
#include <vector>
#include <cassert>

#include <boost/multiprecision/cpp_int.hpp>

namespace funtls { namespace ec {

using field_elem = boost::multiprecision::cpp_int;

field_elem div_mod(const field_elem& a, const field_elem& b, const field_elem& n);

struct point {
    field_elem x;
    field_elem y;
};
static const point infinity{-1, -1}; // HACK, don't depend on the exact value

inline bool operator==(const point& lhs, const point& rhs) {
    return lhs.x == rhs.x && lhs.y == rhs.y;
}

inline bool operator!=(const point& lhs, const point& rhs) {
    return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& os, const point& p);

// Note: generative primtive elliptic curves not supported
// Elliptic curve in GF(p) on the form y^2 = x^3 + ax + b'
struct curve {
    field_elem p; // field prime
    field_elem a; // curve 'a' parameter
    field_elem b; // curve 'b' parameter
    point G; // base point (Gx, Gy)
    field_elem n; // prime 'n' - order of base point
    int h; // co factor #E(F_p)/n

    field_elem mod_p(const field_elem& e) const;

    void check() const;
    bool on_curve(const point& point) const;
    point add(const point& lhs, const point& rhs) const;
    point sqr(const point& point) const;
    point mul(field_elem m, point point) const;
    point mul(const point& point, const field_elem& m) const;
};

extern const curve secp384r1;

} } // namespace funtls::ec

#endif

