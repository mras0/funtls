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
    FUNTLS_CHECK_BINARY(size_, <=, max_bytes, "Invalid representation: " + util::base16_encode(v_, size_));
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
    FUNTLS_CHECK_BINARY(size, <=, max_bytes, "Out of representable range");
    biguint x;
    x.size_ = size;
    std::reverse_copy(bytes, bytes+size, x.v_);
    x.trim();
    x.check_repr();
    return x;
}

bool operator==(const biguint& lhs, const biguint& rhs)
{
    lhs.check_repr();
    rhs.check_repr();
    if (lhs.size_ != rhs.size_) return false;
    return std::equal(lhs.v_, lhs.v_+lhs.size_, rhs.v_);
}

bool operator<(const biguint& lhs, const biguint& rhs)
{
    lhs.check_repr();
    rhs.check_repr();
    if (lhs.size_ < rhs.size_) {
        return true;
    } else if (lhs.size_ > rhs.size_) {
        return false;
    } else {
        assert(lhs.size_ == rhs.size_);
        if (!lhs.size_) return false;
        // Check most siginificant digits for mismatch
        for (biguint::size_type i = lhs.size_-1; i; i--) {
            if (lhs.v_[i] > rhs.v_[i]) {
                return false;
            } else if (lhs.v_[i] < rhs.v_[i]) {
                return true;
            }
        }
        // lhs and rhs are equal up to the least siginificant digit
        return lhs.v_[0] < rhs.v_[0];
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
    if (res.size_ > max_bytes) res.size_--;
    uint16_t sum = 0;
    for (size_type i = 0; i < res.size_; ++i) {
        if (i < ls) sum += lhs.v_[i];
        if (i < rs) sum += rhs.v_[i];
        assert(sum < 512);
        res.v_[i] = static_cast<uint8_t>(sum);
        sum >>= 8;
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

    int16_t d = 0;
    for (unsigned i = 0; i<rhs.size_ || d; ++i) {
        FUNTLS_CHECK_BINARY(i, <, lhs.size_, "Negative number produced");
        d += lhs.v_[i];
        if (i < rhs.size_) d -= rhs.v_[i];
        assert(d >= -511 && d <= 255);
        res.v_[i] = static_cast<uint8_t>(d);
        d >>= 8;
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
    FUNTLS_CHECK_BINARY(res.size_, <, biguint::max_bytes, "Shoud probably clamp instead");

    memset(&res.v_[0], 0, res.size_);
    for (int i = 0, n = res.size_; i < n; ++i) {
        for (int j = std::max(0, i+1-n); j <= std::min(i, n-1); j++) {
            auto k = i - j;
            if (j >= lhs.size_ || k >= rhs.size_) continue;
            uint16_t prod = static_cast<uint16_t>(lhs.v_[j]) * rhs.v_[k];
            uint8_t carry = addc(res.v_[i], static_cast<uint8_t>(prod));
            prod >>= 8;
            assert(prod < 0xff);
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
    lhs.check_repr();
    rhs.check_repr();

    // Handle special cases
    FUNTLS_CHECK_BINARY(rhs.size_, !=, 0, "Division by zero");
    if (!lhs.size_ || (rhs.size_==1 && rhs.v_[0] == 1)) {
        // lhs==0 || rhs==1
        return res = lhs;
    }

    biguint rem;
    divmod(res, rem, lhs, rhs);
    return res;
}

biguint& biguint::mod(biguint& res, const biguint& lhs, const biguint& rhs)
{
    lhs.check_repr();
    rhs.check_repr();

    // Handle special cases
    FUNTLS_CHECK_BINARY(rhs.size_, !=, 0, "Division by zero");
    if (!lhs.size_) return res = lhs;
    // res = 1 -> ret = 0
    if (rhs.size_==1 && rhs.v_[0] == 1) return res = 0;

    biguint quot;
    divmod(quot, res, lhs, rhs);
    return res;
}

void biguint::divmod(biguint& quot, biguint& rem, const biguint& lhs, const biguint& rhs)
{
    if (&quot == &lhs || &quot == &rhs || &rem == &lhs || &rem == &rhs) {
        biguint q, r;
        divmod(q, r, lhs, rhs);
        quot = q;
        rem = r;
        return;
    }
    //std::cout << std::hex << std::uppercase << lhs << " div " << rhs << std::endl;
    quot.size_ = lhs.size_;
    rem.size_ = 0;
    for (size_type i = lhs.size_; i--;) {
        rem <<= 8;
        rem.v_[0] = lhs.v_[i];
        if (!rem.size_ && rem.v_[0]) rem.size_=1;
        quot.v_[i] = 0;
        //std::cout << " i " << i;
        //std::cout << " lhs[i] " << (unsigned)lhs.v_[i];
        //std::cout << " rem " << rem;
        while (rem >= rhs) {
            biguint::sub(rem, rem, rhs);
            //std::cout << " => " << rem;
            quot.v_[i]++;
            assert(quot.v_[i]);
        }
        //std::cout << " qout[i] " << (unsigned)quot.v_[i];
        //std::cout << std::endl;
    }
    quot.trim();

    rem.check_repr();
    quot.check_repr();
    //std::cout << " quot = " << quot << " rem = " << rem << std::endl;
}

biguint& biguint::operator>>=(uint32_t shift)
{
    check_repr();
    const auto shift_bytes = shift >> 3;
    FUNTLS_CHECK_BINARY(shift_bytes, <=, max_bytes, "Invalid shift amount");

    if (size_ <= shift_bytes) {
        size_ = 0;
    } else {
        const auto shift_bits  = shift & 7;
        size_ -= shift_bytes;
        assert(size_ != 0);
        memmove(v_, v_+shift_bytes, size_);
        if (shift_bits) {
            const auto mask = (1 << shift_bits) - 1;
            limb_type carry = 0;
            for (auto i = size_; i--; ) {
                const auto x = v_[i];
                v_[i] = (carry << (8-shift_bits)) | (x >> shift_bits);
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

    const auto shift_bytes = shift >> 3;
    size_ += shift_bytes;
    FUNTLS_CHECK_BINARY(size_, <=, max_bytes, "Invalid shift amount " + std::to_string(shift));

    memmove(v_+shift_bytes, v_, size_-shift_bytes);
    memset(v_, 0, shift_bytes);
    const auto shift_bits  = shift & 7;
    if (shift_bits) {
        limb_type carry = 0;
        for (auto i = shift_bytes; i < size_; ++i) {
            const auto x = v_[i];
            v_[i] = carry | (x << shift_bits);
            carry = x >> (8-shift_bits);
        }
        if (carry != 0) {
            FUNTLS_CHECK_BINARY(size_+1, <=, max_bytes, "Invalid shift amount " + std::to_string(shift));
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
    while (exponent._size()) {
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
        while (i--) {
            const auto x = ui.v_[i];
            const auto f = x>>4;
            const auto l = x&0xf;
            // first nibble might have to be skipped
            if (i + 1 != ui.size_ || f) os << (unsigned) f;
            os << (unsigned) l;
        }
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
