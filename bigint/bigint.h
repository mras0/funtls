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
#if 1
    typedef uint32_t limb_type;
    typedef uint64_t dlimb_type;
#else
    typedef uint8_t  limb_type;
    typedef uint16_t dlimb_type;
#endif

    static constexpr size_type limb_bits = sizeof(limb_type) * 8;
    static constexpr size_type max_bits  = 4096;

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
            v_[size_++] = static_cast<limb_type>(x);
            x >>= limb_bits;
        }
        check_repr();
    }
    explicit biguint(const char* str);

    template<typename T, typename = typename std::enable_if<std::is_integral<T>::value>::type>
    explicit operator T() const {
        T res = 0;
        auto size = (sizeof(T)+sizeof(limb_type)-1) / sizeof(limb_type);
        if (size > size_) size = size_;
        for (size_t i = 0; i < size; ++i) {
            res |= T(v_[i]) << (limb_bits*i);
        }
        return res;
    }

    biguint& operator+=(const biguint& rhs) {
        return add(*this, *this, rhs);
    }
    biguint& operator>>=(uint32_t shift);
    biguint& operator<<=(uint32_t shift);
    biguint operator<<(uint32_t shift) const {
        biguint res(*this);
        return res<<=shift;
    }
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
        if (bits) {
            if (!size_) v_[size_++] = 0;
            v_[0] |= bits;
        }
        return *this;
    }

    static biguint from_be_bytes(const uint8_t* bytes, size_t size);

    static int compare(const biguint& lhs, const biguint& rhs);
    friend std::ostream& operator<<(std::ostream& os, const biguint& ui);

private:
    static constexpr size_type max_size = max_bits / limb_bits;
    limb_type v_[max_size];
    size_type size_;

    void trim() {
        while (size_ && !v_[size_-1]) {
            size_--;
        }
    }
#ifdef NDEBUG
    void check_repr() const {}
#else
    void check_repr() const;
#endif
};

inline bool operator==(const biguint& lhs, const biguint& rhs) {
    return biguint::compare(lhs, rhs) == 0;
}
inline bool operator!=(const biguint& lhs, const biguint& rhs) {
    return biguint::compare(lhs, rhs) != 0;
}
inline bool operator<(const biguint& lhs, const biguint& rhs) {
    return biguint::compare(lhs, rhs) < 0;
}
inline bool operator>(const biguint& lhs, const biguint& rhs) {
    return biguint::compare(lhs, rhs) > 0;
}
inline bool operator>=(const biguint& lhs, const biguint& rhs) {
    return biguint::compare(lhs, rhs) >= 0;
}
inline bool operator<=(const biguint& lhs, const biguint& rhs) {
    return biguint::compare(lhs, rhs) <= 0;
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
class small_lit : public expr {
public:
    small_lit(uintmax_t x) : x_(x) {}
    void eval(biguint& res) const {
        res = x_;
    }
private:
    uintmax_t x_;
};

class lit : public expr {
public:
    lit(const biguint& x) : x_(x) {}
    void eval(biguint& res) const {
        assert(&res != &x_);
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
typename std::enable_if<!is_expr_t<Expr>::value && !std::is_integral<Expr>::value, lit>::type wrap(const Expr& e)
{
    return lit(e);
}

template<typename Expr>
typename std::enable_if<!is_expr_t<Expr>::value && std::is_integral<Expr>::value, small_lit>::type wrap(const Expr& e)
{
    return small_lit(e);
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


