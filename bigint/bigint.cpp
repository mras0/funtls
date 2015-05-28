#include "bigint.h"
#include <ostream>
#include <util/base_conversion.h>
#include <util/test.h>
#include <algorithm>
#include <string.h>

namespace funtls { namespace bigint {

#ifndef NDEBUG
void biguint::check_repr() const
{
    FUNTLS_CHECK_BINARY(size_, <=, max_size, "Invalid representation: " + util::base16_encode(v_, size_));
    if (size_) {
        FUNTLS_CHECK_BINARY((unsigned)v_[size_-1], !=, 0, "Invalid representation: " + util::base16_encode(v_, size_));
    }
}
#endif

biguint::biguint(const char* s)
    : size_(0)
{
    auto slen = strlen(s);
    assert(slen);
    FUNTLS_CHECK_BINARY(slen, >, 0, "Empty string not allowed");

    if (s[0] == '0') {
        if (s[1] == 0) {
            // "0"
        } else {
            // "0???" we only support hex here for now at least
            FUNTLS_CHECK_BINARY((unsigned)s[1],==,'x',"Only hex supported");
            FUNTLS_CHECK_BINARY(slen, >, 2, "Invalid hex string");
            std::string str(s+2, slen-2);
            if (str.size()%2) str.insert(str.begin(),'0');
            auto bytes = util::base16_decode(str);
            *this = from_be_bytes(bytes.data(), bytes.size());
        }
    } else {
        // decimal number
        for (; *s; s++) {
            if (*s < '0' || *s > '9') {
                FUNTLS_CHECK_FAILURE("\"" + std::string(s) + "\" is not a valid decimal number");
            }
            *this = *this * 10 + (*s - '0');
        }
    }

    check_repr();
}

biguint biguint::from_be_bytes(const uint8_t* bytes, size_t size)
{
    FUNTLS_CHECK_BINARY(size, <=, sizeof(v_), "Out of representable range");
    biguint x;
    x.size_ = (size+sizeof(limb_type)-1)/sizeof(limb_type);
    if (x.size_) x.v_[x.size_-1] = 0; // Final limb might be partial
    std::reverse_copy(bytes, bytes+size, reinterpret_cast<uint8_t*>(x.v_));
    x.trim();
    x.check_repr();
    return x;
}

int biguint::compare(const biguint& lhs, const biguint& rhs)
{
    lhs.check_repr();
    rhs.check_repr();
    if (lhs.size_ < rhs.size_) {
        return -1;
    } else if (lhs.size_ > rhs.size_) {
        return 1;
    } else {
        assert(lhs.size_ == rhs.size_);
        if (!lhs.size_) return 0;
        // Check most siginificant digits for mismatch
        for (biguint::size_type i = lhs.size_-1; i; i--) {
            if (lhs.v_[i] > rhs.v_[i]) {
                return 1;
            } else if (lhs.v_[i] < rhs.v_[i]) {
                return -1;
            }
        }
        // lhs and rhs are equal up to the least siginificant digit
        const auto diff = lhs.v_[0] - rhs.v_[0];
        return diff < 0 ? -1 : diff > 0 ? 1 : 0;
    }
}

biguint& biguint::add(biguint& res, const biguint& lhs, const biguint& rhs)
{
    lhs.check_repr();
    rhs.check_repr();

    // Handle 0
    if (!lhs.size_) return res = rhs;
    if (!rhs.size_) return res = lhs;

    const auto ls = lhs.size_;
    const auto rs = rhs.size_;

    res.size_ = 1 + std::max(ls, rs);
    if (res.size_ > max_size) res.size_--;
    dlimb_type sum = 0;
    for (size_type i = 0; i < res.size_; ++i) {
        if (i < ls) sum += lhs.v_[i];
        if (i < rs) sum += rhs.v_[i];
        assert(sum < (dlimb_type(2)<<limb_bits));
        res.v_[i] = static_cast<limb_type>(sum);
        sum >>= limb_bits;
    }
    res.trim();
    res.check_repr();
    return res;
}

biguint& biguint::sub(biguint& res, const biguint& lhs, const biguint& rhs)
{
    lhs.check_repr();
    rhs.check_repr();

    // Handle 0
    if (!rhs.size_) return res = lhs;
    FUNTLS_CHECK_BINARY(lhs.size_, !=, 0, "0-X not allowed");
    FUNTLS_CHECK_BINARY(lhs.size_, >=, rhs.size_, "Would produce negative number");

    if (&res != &lhs) res = lhs;

    std::make_signed<dlimb_type>::type d = 0;
    for (unsigned i = 0; i<rhs.size_ || d; ++i) {
        FUNTLS_CHECK_BINARY(i, <, lhs.size_, "Negative number produced");
        d += lhs.v_[i];
        if (i < rhs.size_) d -= rhs.v_[i];
        assert(d >= -((limb_type(2)<<limb_bits)-1) && d <= (limb_type(1)<<limb_bits));
        res.v_[i] = static_cast<limb_type>(d);
        d >>= limb_bits;
    }
    assert(d==0);

    res.trim();
    res.check_repr();
    return res;
}

template<typename T>
bool addc(T& a, T b) {
    const T old = a;
    a += b;
    return a < old;
}

biguint& biguint::mul(biguint& res, const biguint& lhs, const biguint& rhs)
{
    lhs.check_repr();
    rhs.check_repr();

    if (&res == &lhs || &res == &rhs) {
        biguint tmp;
        return res = biguint::mul(tmp, lhs, rhs);
    }

    // Handle 0
    if (!lhs.size_) return res = lhs;
    if (!rhs.size_) return res = rhs;

    res.size_ = 2 * std::max(lhs.size_, rhs.size_);
    FUNTLS_CHECK_BINARY(res.size_, <=, biguint::max_size, "Shoud probably clamp instead");

    memset(&res.v_[0], 0, sizeof(limb_type)*res.size_);
    for (int i = 0, n = res.size_; i < n; ++i) {
        const int jmin = std::max(0, i - rhs.size_ + 1);
        const int jmax = std::min(i + 1, static_cast<int>(lhs.size_));
        for (int j = jmin; j < jmax; j++) {
            auto k = i - j;
            assert(k >= 0 && k < rhs.size_);
            dlimb_type prod = static_cast<dlimb_type>(lhs.v_[j]) * rhs.v_[k];
            limb_type carry = addc(res.v_[i], static_cast<limb_type>(prod));
            prod >>= limb_bits;
            assert(prod < (dlimb_type(1)<<limb_bits));
            carry += prod;
            for (auto q = i+1; carry && q < n; ++q) {
                carry = addc(res.v_[q], carry);
            }
        }
    }
    res.trim();
    res.check_repr();
    return res;
}

biguint& biguint::div(biguint& res, const biguint& lhs, const biguint& rhs)
{
    biguint rem;
    divmod(res, rem, lhs, rhs);
    return res;
}

biguint& biguint::mod(biguint& res, const biguint& lhs, const biguint& rhs)
{
    biguint quot;
    divmod(quot, res, lhs, rhs);
    return res;
}

void biguint::divmod(biguint& quot, biguint& rem, const biguint& lhs, const biguint& rhs)
{
    assert(&quot != &rem);
    lhs.check_repr();
    rhs.check_repr();

    //
    // Handle zeros
    //
    FUNTLS_CHECK_BINARY(rhs.size_, !=, 0, "Division by zero");
    if (!lhs.size_) {
        // 0/X: quot = rem = 0
        quot.size_ = rem.size_ = 0;
        return;
    }

    // Now: lhs != 0 && rhs != 0 (also implies that the sizes are greater than 0)
    const auto ls = lhs.size_;
    const auto rs = rhs.size_;
    assert(ls > 0 && rs > 0);

    //
    // The cases where lhs <= rhs are trivially handled.
    //
    const auto compare_result = biguint::compare(lhs, rhs);
    if (compare_result < 0) {         // lhs < rhs
        rem = lhs;
        quot.size_ = 0;
        return;
    } else if (compare_result == 0) { // lhs == rhs
        quot = 1;
        rem.size_ = 0;
        return;
    }

    //
    // Handle directly calculable cases
    //
    if (ls == 1) {
        const auto l = lhs.v_[0];
        if (rs == 1) {
            const auto r = rhs.v_[0];
            quot = l / r;
            rem  = l % r;
            return;
        } else if (rs == 2) {
            const auto r = (dlimb_type(rhs.v_[1])<<limb_bits) | rhs.v_[0];
            quot = l / r;
            rem  = l % r;
            return;
        }
    } else if (ls == 2) {
        const auto l = (dlimb_type(lhs.v_[1])<<limb_bits) | lhs.v_[0];
        if (rs == 1) {
            const auto r = rhs.v_[0];
            quot = l / r;
            rem  = l % r;
            return;
        } else if (rs == 2) {
            const auto r = (dlimb_type(rhs.v_[1])<<limb_bits) | rhs.v_[0];
            quot = l / r;
            rem  = l % r;
            return;
        }
    }

    //
    // We're now in a confirmed hard case. Make sure we're not aliasing
    //
    if (&quot == &lhs || &quot == &rhs || &rem == &lhs || &rem == &rhs) {
        biguint q, r;
        divmod(q, r, lhs, rhs);
        quot = q;
        rem = r;
        return;
    }

    assert(lhs > rhs);

    quot.size_ = lhs.size_;
    rem.size_ = 0;
    for (size_type i = lhs.size_; i--;) {
        rem <<= limb_bits;
        rem.v_[0] = lhs.v_[i];
        if (!rem.size_ && rem.v_[0]) rem.size_=1;
        quot.v_[i] = 0;
        while (rem >= rhs) {
            biguint::sub(rem, rem, rhs);
            quot.v_[i]++;
            assert(quot.v_[i]);
        }
    }
    quot.trim();

    rem.check_repr();
    quot.check_repr();
}

biguint& biguint::operator>>=(uint32_t shift)
{
    check_repr();
    const auto shift_limbs = shift / limb_bits;
    FUNTLS_CHECK_BINARY(shift_limbs, <=, max_size, "Invalid shift amount");

    if (size_ <= shift_limbs) {
        size_ = 0;
    } else {
        const auto shift_bits  = shift % limb_bits;
        size_ -= shift_limbs;
        assert(size_ != 0);
        memmove(v_, v_+shift_limbs, size_*sizeof(limb_type));
        if (shift_bits) {
            const auto mask = (1 << shift_bits) - 1;
            limb_type carry = 0;
            for (auto i = size_; i--; ) {
                const auto x = v_[i];
                v_[i] = (carry << (limb_bits-shift_bits)) | (x >> shift_bits);
                carry = x & mask;
            }
        }
        if (!v_[size_-1]) size_--;
    }
    check_repr();
    return *this;
}

biguint& biguint::operator<<=(uint32_t shift)
{
    check_repr();

    if (!size_) return *this;

    const auto shift_limbs = shift / limb_bits;
    size_ += shift_limbs;
    FUNTLS_CHECK_BINARY(size_, <=, max_size, "Invalid shift amount " + std::to_string(shift));

    memmove(v_+shift_limbs, v_, sizeof(limb_type)*(size_-shift_limbs));
    memset(v_, 0, sizeof(limb_type)*shift_limbs);
    const auto shift_bits  = shift % limb_bits;
    if (shift_bits) {
        limb_type carry = 0;
        for (auto i = shift_limbs; i < size_; ++i) {
            const auto x = v_[i];
            v_[i] = carry | (x << shift_bits);
            carry = x >> (limb_bits-shift_bits);
        }
        if (carry != 0) {
            FUNTLS_CHECK_BINARY(size_+1, <=, max_size, "Invalid shift amount " + std::to_string(shift));
            v_[size_++] = carry;
        }
    }
    check_repr();
    return *this;
}

biguint& biguint::pow(biguint& res, const biguint& lhs, const biguint& rhs, const biguint& n)
{
    if (&res == &lhs || &res == &rhs || &res == &n) {
        biguint tmp;
        return res = biguint::pow(tmp, lhs, rhs, n);
    }

    res = 1;
    biguint base;
    biguint::mod(base, lhs, n);

    biguint exponent=rhs;
    while (exponent.size_) {
        if (exponent & 1) {
            biguint::mul(res, res, base);
            biguint::mod(res, res, n);
        }
        exponent >>= 1;
        biguint::mul(base, base, base);
        biguint::mod(base, base, n);
    }
    return res;
}

std::ostream& operator<<(std::ostream& os, const biguint& ui)
{
    ui.check_repr();
    const auto base     = os.flags() & std::ios::basefield;
    const auto showbase = os.flags() & std::ios::showbase;
    if (base == std::ios::hex) {
        if (showbase) os << "0x";
        size_t i = ui.size_;
        if (!i) return os << "0";
        std::string s;
        const char* const hexchars = os.flags() & std::ios::uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
        while (i--) {
            const auto x = ui.v_[i];
            for (int j = biguint::limb_bits - 4; j >= 0; j -= 4) {
                s += hexchars[(x>>j)&0xf];
            }
        }
        while (s.front() == '0') {
            s.erase(s.begin());
            assert(!s.empty());
        }
        os << s;
    } else if (base == std::ios::dec) {
        biguint rem;
        auto n = ui;
        std::string s;
        do {
            biguint::divmod(n, rem, n, 10);
            assert(rem < 10);
            s += '0' + static_cast<uint8_t>(rem);
        } while (n != 0);
        for (auto it = s.crbegin(), end = s.crend(); it != end; ++it) {
            os << *it;
        }
    }
    return os;
}

} } // namespace funtls::bigint
