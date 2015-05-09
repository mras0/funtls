#include "ec.h"
#include <util/test.h>

#include <boost/multiprecision/miller_rabin.hpp>

using namespace funtls;

namespace {

// TODO: make these should probably be moved to util
template<typename int_type>
bool is_prime(const int_type& n) {
    return miller_rabin_test(n, 25);
}

template<typename a_expr, typename int_type>
int_type pmod(const a_expr& a, const int_type& p) {
    int_type res = a % p;
    if (res < 0) res += p;
    assert(res >= 0 && res < p);
    return res;
}

template<typename int_type>
int_type modular_inverse(const int_type& a, const int_type& n)
{
    int_type r = n, newr = pmod(a, n);
    int_type t = 0, newt = 1;
    while (newr) {
        int_type quotient = r / newr;
        int_type saved = newt;
        newt = t - quotient * saved;
        t = saved;
        saved = newr;
        newr = r - quotient * saved;
        r = saved;
    }
    assert(r <= 1);
    if (t < 0) t += n;
    assert(pmod(int_type(a*t), n) == 1);
    return t;
}

} // unnamed namespace

namespace funtls { namespace ec {

field_elem div_mod(const field_elem& a, const field_elem& b, const field_elem& n)
{
    return pmod(a * modular_inverse(b, n), n);
}

std::ostream& operator<<(std::ostream& os, const point& p) {
    if (p == infinity) {
        return os << "inf";
    }
    return os << "(" << p.x << ", " << p.y << ")";
}

field_elem curve::mod_p(const field_elem& e) const
{
    return pmod(e, p);
}

void curve::check() const {
    static const char* deferrmsg = "Invalid curve parameter";
    FUNTLS_CHECK_BINARY(is_prime(p), ==, true, deferrmsg);
    FUNTLS_CHECK_BINARY(a,   >=, 0, deferrmsg);
    FUNTLS_CHECK_BINARY(a,   <,  p, deferrmsg);
    FUNTLS_CHECK_BINARY(b,   >=, 0, deferrmsg);
    FUNTLS_CHECK_BINARY(b,   <,  p, deferrmsg);
    FUNTLS_CHECK_BINARY(G.x, >=, 0, deferrmsg);
    FUNTLS_CHECK_BINARY(G.x, <,  p, deferrmsg);
    FUNTLS_CHECK_BINARY(G.y, >=, 0, deferrmsg);
    FUNTLS_CHECK_BINARY(G.y, <,  p, deferrmsg);
    FUNTLS_CHECK_BINARY(on_curve(G), ==, true, deferrmsg);
    FUNTLS_CHECK_BINARY(is_prime(n), ==, true, deferrmsg);

    // 4*a^3 + 27*b^2 != 0 (mod p)
    const field_elem discriminant = mod_p(4 * field_elem(powm(a, 3, p)) + 27 * field_elem(powm(b, 2, p)));
    FUNTLS_CHECK_BINARY(discriminant, !=, 0, "Invalid elliptic curve: 4*a^3 + 27*b^2 == 0 (mod p)");

    // #E(F_p) != p
    const field_elem F_p_size = n * h;
    FUNTLS_CHECK_BINARY(F_p_size, !=, p, "Invalid elliptic curve: #(F_p) == p");

    // h <= 4
    FUNTLS_CHECK_BINARY(h, >, 0, "Invalid curve: Invalid co factor");
    FUNTLS_CHECK_BINARY(h, <=, 4, "Invalid curve: Invalid co factor");

    // p^B != 1 for 1 <= B <= 20
    field_elem pB = p;
    for (int B = 1; B < 20; ++B) {
        FUNTLS_CHECK_BINARY(pB, !=, 1, "Invalid elliptic curve: p^" + std::to_string(B) + " == 1 (mod p)");
        pB = (pB * p) % n;
    }
}

bool curve::on_curve(const point& point) const {
    assert(point != infinity);
    if (point.x < 0 || point.x >= p) {
        assert(false);
        return false;
    }
    if (point.y < 0 || point.y >= p) {
        assert(false);
        return false;
    }
    const field_elem y2   = powm(point.y, 2, p);
    const field_elem xexp = mod_p(field_elem(powm(point.x, 3, p)) + a * point.x + b);
    return y2 == xexp;
}

point curve::add(const point& lhs, const point& rhs) const {
    if (lhs == infinity) {
        return rhs;
    } else if (rhs == infinity) {
        return lhs;
    }
    assert(on_curve(lhs));
    assert(on_curve(rhs));
    if (lhs == rhs) {
        if (lhs.y == 0) {
            return infinity;
        }
        return sqr(lhs);
    }
    if (lhs.x == rhs.x) {
        assert(lhs.y != rhs.y);
        return infinity;
    }
    assert(lhs.x != rhs.x);
    const field_elem lambda = div_mod(rhs.y - lhs.y, rhs.x - lhs.x, p);
    const field_elem x      = mod_p(lambda*lambda - lhs.x - rhs.x);
    const field_elem y      = mod_p(lambda*(lhs.x-x) - lhs.y);
    assert(on_curve({x,y}));
    return {x, y};
}

point curve::sqr(const point& point) const {
    assert(on_curve(point));
    assert(point.y != 0);
    const field_elem lambda = div_mod(3*point.x*point.x + a, 2*point.y, p);
    const field_elem x      = mod_p(lambda*lambda - 2*point.x);
    const field_elem y      = mod_p(lambda*(point.x-x) - point.y);
    assert(on_curve({x,y}));
    return {x, y};
}

point curve::mul(field_elem m, point point) const {
    assert(on_curve(point));
    assert(m > 0);

    ec::point res = infinity;
    while (m) {
        if (m & 1) res = add(res, point);
        point = sqr(point);
        m >>= 1;
    }
    assert(res.x < p);
    assert(res.y < p);
    assert(res == infinity || on_curve(res));
    return res;
}

point curve::mul(const point& point, const field_elem& m) const {
    return mul(m, point);
}

const curve secp256r1 {
    /* p  */ field_elem("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
    /* a  */ field_elem("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
    /* b  */ field_elem("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            {
    /* Gx */ field_elem("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
    /* Gy */ field_elem("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            },
    /* n  */ field_elem("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
    1,
};
const curve secp384r1 {
    /* p  */ field_elem("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319"),
    /* a  */ field_elem("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"),
    /* b  */ field_elem("0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),
            {
    /* Gx */ field_elem("0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
    /* Gy */ field_elem("0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"),
            },
    /* n  */ field_elem("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
    1,
};
} } // namespace funtls::ec
