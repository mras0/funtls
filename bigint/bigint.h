#ifndef FUNTLS_BIGINT_BIGINT_H_INCLUDED
#define FUNTLS_BIGINT_BIGINT_H_INCLUDED

#include <cassert>
#include <stdint.h>
#include <iosfwd>

#include <utility>     // forward
#include <type_traits> // enable_if

namespace funtls { namespace bigint {

namespace detail {
struct expr {};
template<typename Expr>
using is_expr_t = std::is_base_of<expr, Expr>;
} // namespace detail


class biguint {
public:
    typedef uint16_t size_type;
    typedef uint8_t  limb_type;
    static constexpr size_type max_bytes = 4096;
    static constexpr size_t max_bits  = 8 * max_bytes;

    biguint() : size_(0) {
        check_repr();
    }
    template<typename Expr, typename =typename std::enable_if<detail::is_expr_t<Expr>::value>::type>
    biguint(const Expr& expr) : size_(0) {
        expr.eval(*this);
        check_repr();
    }
    biguint(uintmax_t x) : size_(0) {
        static_assert(sizeof(x) < sizeof(v_), "");
        while (x) {
            v_[size_++] = static_cast<uint8_t>(x);
            x >>= 8;
        }
        check_repr();
    }
    explicit biguint(const char* str);

    template<typename T, typename = typename std::enable_if<std::is_integral<T>::value>::type>
    explicit operator T() const {
        T res = 0;
        auto size = size_;
        if (size > sizeof(T)) size = sizeof(T);
        for (size_t i = 0; i < size; ++i) {
            res |= T(v_[i]) << (8*i);
        }
        return res;
    }

    biguint& operator+=(const biguint& rhs) {
        return add(*this, *this, rhs);
    }
    biguint& operator>>=(uint32_t shift);
    biguint& operator<<=(uint32_t shift);
    static biguint& add(biguint& res, const biguint& lhs, const biguint& rhs);
    static biguint& sub(biguint& res, const biguint& lhs, const biguint& rhs);
    static biguint& mul(biguint& res, const biguint& lhs, const biguint& rhs);
    static biguint& div(biguint& res, const biguint& lhs, const biguint& rhs);
    static biguint& mod(biguint& res, const biguint& lhs, const biguint& rhs);

    static void divmod(biguint& quot, biguint& rem, const biguint& lhs, const biguint& rhs);
    static biguint& pow(biguint& res, const biguint& lhs, const biguint& rhs, const biguint& mod);

    limb_type operator&(limb_type mask) const {
        if (!size_) return 0;
        return v_[0] & mask;
    }
    biguint& operator|=(limb_type bits) {
        if (!size_) v_[size_++] = 0;
        v_[0] |= bits;
        return *this;
    }

    static biguint from_be_bytes(const uint8_t* bytes, size_t size);

    friend bool operator==(const biguint& lhs, const biguint& rhs);
    friend bool operator<(const biguint& lhs, const biguint& rhs);
    friend std::ostream& operator<<(std::ostream& os, const biguint& ui);

    // "secret" accessors. TODO: remove
    size_type _size() const { return size_; }
    uint8_t* _v() { return v_; }
    const uint8_t* _v() const { return v_; }

private:
    size_type size_;
    uint8_t  v_[max_bytes];

    void trim() {
        while (size_ && !v_[size_-1]) {
            size_--;
        }
    }
    void check_repr() const;
};

inline bool operator!=(const biguint& lhs, const biguint& rhs) {
    return !(lhs == rhs);
}

inline bool operator>(const biguint& lhs, const biguint& rhs) {
    return rhs < lhs;
}

inline bool operator>=(const biguint& lhs, const biguint& rhs) {
    return !(lhs < rhs);
}

inline bool operator<=(const biguint& lhs, const biguint& rhs) {
    return !(lhs > rhs);
}


enum class bin_expr_tag { add, sub, mul, div, mod };

template<bin_expr_tag tag, typename L, typename R>
class bin_expr : public detail::expr {
public:
    bin_expr(const L& l, const R& r) : l_(l), r_(r) {}
    void eval(biguint& res) const {
        biguint& (*op)(biguint&, const biguint&, const biguint&);
        switch (tag) {
        case bin_expr_tag::add: op = &biguint::add; break;
        case bin_expr_tag::sub: op = &biguint::sub; break;
        case bin_expr_tag::mul: op = &biguint::mul; break;
        case bin_expr_tag::div: op = &biguint::div; break;
        case bin_expr_tag::mod: op = &biguint::mod; break;
        }
        assert(op);
        op(res, l_, r_);
    }
private:
    L l_;
    R r_;
};

namespace detail {
class lit : public expr {
public:
    lit(const biguint& x) : x_(x) {}
    void eval(biguint& res) const {
        res = x_;
    }
private:
    const biguint& x_;
};

template<bin_expr_tag tag, typename L, typename R>
bin_expr<tag, L, R> make_bin_expr(L&& l, R&& r) {
    return bin_expr<tag, L, R>(std::forward<L>(l), std::forward<R>(r));
}

template<typename Expr>
typename std::enable_if<is_expr_t<Expr>::value, const Expr&>::type wrap(const Expr& e)
{
    return e;
}

template<typename Expr>
typename std::enable_if<!is_expr_t<Expr>::value, lit>::type wrap(const Expr& e)
{
    return lit(e);
}
} // namespace detail

template<typename L, typename R>
auto operator+(const L& lhs, const R& rhs) -> decltype(detail::make_bin_expr<bin_expr_tag::add>(detail::wrap(lhs), detail::wrap(rhs))) {
    return detail::make_bin_expr<bin_expr_tag::add>(detail::wrap(lhs), detail::wrap(rhs));
}

template<typename L, typename R>
auto operator-(const L& lhs, const R& rhs) -> decltype(detail::make_bin_expr<bin_expr_tag::sub>(detail::wrap(lhs), detail::wrap(rhs))) {
    return detail::make_bin_expr<bin_expr_tag::sub>(detail::wrap(lhs), detail::wrap(rhs));
}

template<typename L, typename R>
auto operator*(const L& lhs, const R& rhs) -> decltype(detail::make_bin_expr<bin_expr_tag::mul>(detail::wrap(lhs), detail::wrap(rhs))) {
    return detail::make_bin_expr<bin_expr_tag::mul>(detail::wrap(lhs), detail::wrap(rhs));
}

template<typename L, typename R>
auto operator/(const L& lhs, const R& rhs) -> decltype(detail::make_bin_expr<bin_expr_tag::div>(detail::wrap(lhs), detail::wrap(rhs))) {
    return detail::make_bin_expr<bin_expr_tag::div>(detail::wrap(lhs), detail::wrap(rhs));
}

template<typename L, typename R>
auto operator%(const L& lhs, const R& rhs) -> decltype(detail::make_bin_expr<bin_expr_tag::mod>(detail::wrap(lhs), detail::wrap(rhs))) {
    return detail::make_bin_expr<bin_expr_tag::mod>(detail::wrap(lhs), detail::wrap(rhs));
}

template<typename L, typename R>
biguint powm(const L& lhs, const R& rhs, const biguint& n) {
    biguint tmp;
    return biguint::pow(tmp, lhs, rhs, n);
}

} } // namespace funtls::bigint

#endif


