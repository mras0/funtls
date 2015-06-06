#include "bigint.h"
#include <ostream>
#include <util/base_conversion.h>
#include <util/test.h>
#include <algorithm>
#include <string.h>

//#define DIVIDE_DEBUG

#ifdef DIVIDE_DEBUG
#include <iostream>
#include <iomanip>
struct wrapped {
    wrapped(funtls::bigint::biguint::dlimb_type i) : i(i){}
    funtls::bigint::biguint::dlimb_type i;
    friend std::ostream& operator<<(std::ostream& os, wrapped w) {
        assert(std::ios::hex == (os.flags() & std::ios::basefield));
        uint64_t hi = static_cast<funtls::bigint::biguint::limb_type>(w.i>>funtls::bigint::biguint::limb_bits);
        uint64_t lo = static_cast<funtls::bigint::biguint::limb_type>(w.i);
        if (!hi) {
            return os << lo;
        }
        os << hi;
        const auto fill = os.fill();
        os << std::setfill('0') << std::setw(funtls::bigint::biguint::limb_bits/4) << lo;
        os << std::setfill(fill);
        return os;
    }
};
#endif

namespace funtls { namespace bigint {

constexpr biguint::size_type biguint::max_size;

#ifndef NDEBUG
void biguint::check_repr() const
{
    FUNTLS_CHECK_BINARY(size_, <=, max_size, "Invalid representation: " + util::base16_encode(v_, size_));
    if (size_) {
        FUNTLS_CHECK_BINARY(v_[size_-1], !=, 0, "Invalid representation: " + util::base16_encode(v_, size_));
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
        for (biguint::size_type i = lhs.size_; i--;) {
            if (lhs.v_[i] < rhs.v_[i]) return -1;
            if (lhs.v_[i] > rhs.v_[i]) return 1;
        }
        return 0;
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
    if (lhs.size_ == 0 || (lhs.size_ < rhs.size_) || (lhs.size_ == rhs.size_ && lhs.v_[lhs.size_-1] < rhs.v_[rhs.size_-1])) {
        FUNTLS_CHECK_FAILURE("Negative number would be produced");
    }

    detail::dlimb_type<limb_type>::stype d = 0;
    size_type i = 0;
    for (; i < rhs.size_; ++i) {
        d += lhs.v_[i];
        d -= rhs.v_[i];
        res.v_[i] = static_cast<limb_type>(d);
        d >>= limb_bits;
    }
    for (; i < lhs.size_; ++i) {
        assert(i < lhs.size_);
        d += lhs.v_[i];
        res.v_[i] = static_cast<limb_type>(d);
        d >>= limb_bits;
    }
    res.size_ = lhs.size_;
    assert(!d);

    res.trim();
    res.check_repr();
    return res;
}

biguint& biguint::mul(biguint& res, const biguint& lhs, const biguint& rhs)
{
    lhs.check_repr();
    rhs.check_repr();

    //
    // Handle 0
    //
    if (!lhs.size_) return res = lhs;
    if (!rhs.size_) return res = rhs;

    const auto ls = lhs.size_;
    const auto rs = rhs.size_;

    //
    // Handle trivial cases
    //
    if (ls == 1 && rs == 1) {
        return res = static_cast<dlimb_type>(lhs.v_[0]) * rhs.v_[0];
    } else if (ls == 1 || rs == 1) {
        limb_type m;
        if (ls == 1) {
            m = lhs.v_[0];
            if (&res != &rhs) res = rhs;
        } else {
            m = rhs.v_[0];
            if (&res != &lhs) res = lhs;
        }
        dlimb_type carry = 0;
        for (size_type i = 0; i < res.size_; ++i) {
            carry += static_cast<dlimb_type>(res.v_[i]) * m;
            res.v_[i] = static_cast<limb_type>(carry);
            carry >>= limb_bits;
        }
        if (carry && res.size_ < biguint::max_size) {
            assert((carry>>limb_bits)==0);
            res.v_[res.size_++] = static_cast<limb_type>(carry);
        }
        res.check_repr();
        return res;
    }

    if (&res == &lhs || &res == &rhs) {
        biguint tmp;
        return res = biguint::mul(tmp, lhs, rhs);
    }

    res.size_ = std::min(biguint::max_size, static_cast<size_type>(lhs.size_ + rhs.size_));

    memset(&res.v_[0], 0, sizeof(limb_type)*res.size_);

    const auto n  = res.size_;
    for (size_type i = 0; i < ls; ++i) {
        const int jmax = std::min(rs, static_cast<size_type>(n - i));
        dlimb_type carry = 0;
        for (size_type j = 0; j < jmax; ++j) {
            assert(i + j < res.size_);
            carry += static_cast<dlimb_type>(lhs.v_[i]) * rhs.v_[j];
            carry += res.v_[i + j];
            res.v_[i + j] = static_cast<limb_type>(carry);
            carry >>= limb_bits;
        }
        if (i + rs < n) {
            res.v_[i + rs] = static_cast<limb_type>(carry);
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

biguint::limb_type biguint::div_guess(const biguint& rem, const biguint& rhs)
{
    assert(rem >= rhs);
    dlimb_type rem_msl = dlimb_type(rem.v_[rem.size_-1]) << limb_bits;
    if (rem.size_ > 1) {
        rem_msl |= rem.v_[rem.size_-2];
    }
    dlimb_type rhs_msl = dlimb_type(rhs.v_[rhs.size_-1]);
    if (rem.size_ == rhs.size_) {
        rhs_msl <<= limb_bits;
        if (rhs.size_ > 1) {
            rhs_msl |= rhs.v_[rhs.size_-2];
        }
    }

#ifdef DIVIDE_DEBUG
    //std::cout << " rem " << rem;
    //std::cout << " rem_msl " << wrapped(rem_msl);
    //std::cout << " rhs_msl " << wrapped(rhs_msl);
    //std::cout << std::flush;
#endif
    assert(rem_msl >= rhs_msl);
    dlimb_type guess = rem_msl / rhs_msl;
#ifdef DIVIDE_DEBUG
    //std::cout << " guess " << wrapped(guess);
#endif

    static constexpr limb_type limb_max = ~limb_type(0);
    if (guess > limb_max) {
        guess = limb_max;
#ifdef DIVIDE_DEBUG
        //std::cout << " guess " << wrapped(guess);
        //std::cout << std::flush;
#endif
    }

    return static_cast<limb_type>(guess);
}

void biguint::divmod(biguint& quot, biguint& rem, const biguint& lhs, const biguint& rhs)
{
    assert(&quot != &rem);
    lhs.check_repr();
    rhs.check_repr();

    const auto ls = lhs.size_;
    const auto rs = rhs.size_;
    //
    // Handle zeros
    //
    FUNTLS_CHECK_BINARY(rs, !=, 0, "Division by zero");
    if (!ls) {
        // 0/X: quot = rem = 0
        quot.size_ = rem.size_ = 0;
        return;
    }

    // Now: lhs != 0 && rhs != 0 (also implies that the sizes are greater than 0)
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
        assert(rs == 1);
        const auto l = lhs.v_[0];
        const auto r = rhs.v_[0];
        quot = l / r;
        rem  = l % r;
        return;
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
    } else if (rs == 1) {
        quot.size_ = lhs.size_;
        dlimb_type r = 0;
        for (size_type i = lhs.size_; i--;) {
            assert((r>>limb_bits) == 0);
            r <<= limb_bits;
            r |= lhs.v_[i];
            if (r >= rhs.v_[0]) {
                quot.v_[i] = r / rhs.v_[0];
                r -= static_cast<dlimb_type>(quot.v_[i]) * rhs.v_[0];
            } else {
                quot.v_[i] = 0;
            }
        }
        rem = r;
        quot.trim();
        quot.check_repr();
        rem.check_repr();
        return;
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
    assert(rs > 1);

    quot.size_ = lhs.size_;
    rem.size_ = 0;
#if 0
    for (size_type i = lhs.size_; i--;) {
        quot.v_[i] = 0;
        for (auto bit = limb_bits; bit--;) {
            rem <<= 1;
            if ((lhs.v_[i] >> bit) & 1) {
                if (!rem.size_) { rem.size_ = 1; rem.v_[0] = 0; }
                rem.v_[0] |= 1;
            }
            if (rem >= rhs) {
                quot.v_[i] |= limb_type(1) << bit;
                biguint::sub(rem, rem, rhs);
            }
        }
    }
#else

#ifdef DIVIDE_DEBUG
    std::cout << std::hex << std::uppercase << "lhs " << lhs << " rhs " << rhs << std::endl;
#endif
    for (size_type i = lhs.size_; i--;) {
        rem <<= limb_bits;
        rem |= lhs.v_[i];
        quot.v_[i] = 0;

        if (rem < rhs) {
            continue;
        }

        quot.v_[i] = div_guess(rem, rhs);
        assert(quot.v_[i]);
        biguint tmp = quot.v_[i] * rhs;
#ifdef DIVIDE_DEBUG
        std::cout << " quot[i] " << wrapped(quot.v_[i]);
        std::cout << " tmp " << tmp;
#endif
        unsigned padj = 0, madj = 0;
        while (tmp > rem) {
            biguint error = tmp - rem;
#ifdef DIVIDE_DEBUG
            std::cout << "\n  error " << error << std::flush;
#endif
            if (error < rhs) {
                quot.v_[i]--;
                tmp = tmp - rhs;
                break;
            }
            const limb_type guess2 = div_guess(error, rhs);
            const biguint tmp2 = guess2 * rhs;
#ifdef DIVIDE_DEBUG
            std::cout << " guess2 " << wrapped(guess2) << " tmp2 " << tmp2 << std::flush;
#endif
            ++madj;
            quot.v_[i] -= guess2;
            tmp = tmp - tmp2;
        }
        assert(tmp <= rem);
        rem = rem - tmp;
        while (rem >= rhs) {
#ifdef DIVIDE_DEBUG
            std::cout << "\n  error -" << biguint(rem-rhs);
#endif
            ++padj;
            limb_type guess2 = div_guess(rem-rhs, rhs);
            biguint tmp2 = guess2*rhs;
#ifdef DIVIDE_DEBUG
            std::cout << " guess2 " << wrapped(guess2) << " tmp2 " << tmp2 << std::flush;
#endif
            quot.v_[i] += guess2;
            rem = rem - tmp2;
        }
#ifdef DIVIDE_DEBUG
        std::cout << std::endl;
#endif
        assert(rem < rhs);
        assert(quot.v_[i]);
#ifdef DIVIDE_DEBUG
        if (madj+padj) {
            std::cout << "madj = " << madj << " padj = " << padj << std::endl;
            std::cout << "Final quot: "  << wrapped(quot.v_[i]) << std::endl;
            if((madj&&padj) || madj+padj>2)abort();
        }
#endif
        assert(!(madj && padj));
        assert(madj+padj <= 2);
    }
#endif

    quot.trim();

    rem.check_repr();
    quot.check_repr();

    assert(rem <= lhs);
    assert(rem < rhs);
    assert(quot <= lhs);
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
            const auto mask = (limb_type(1) << shift_bits) - 1;
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
            assert(!ui || n < ui);
        } while (n != 0);
        for (auto it = s.crbegin(), end = s.crend(); it != end; ++it) {
            os << *it;
        }
    }
    return os;
}

biguint& biguint::operator&=(const biguint& rhs) {
    if (size_ > rhs.size_) size_ = rhs.size_;
    if (size_) {
        for (auto i = size_; i--;) {
            v_[i] &= rhs.v_[i];
        }
        trim();
    }
    check_repr();
    return *this;
}

bool miller_rabin_test(const biguint& n, unsigned g)
{
    assert(g > 1);
    if (n < 2) return false;        // 0,1  -> not prime
    if (n < 3) return true;         // 2,3  -> prime
    if ((n & 1) == 0) return false; // even -> not prime
    // TODO
    return true; // probably prime
}

} } // namespace funtls::bigint
