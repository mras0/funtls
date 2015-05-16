#include "bigint.h"
#include <ostream>
#include <util/base_conversion.h>
#include <util/test.h>
#include <algorithm>
#include <string.h>

namespace funtls { namespace bigint {

void biguint::check_repr() const
{
    FUNTLS_CHECK_BINARY(size_, <=, max_bytes, "Invalid representation");
    if (size_) {
        FUNTLS_CHECK_BINARY((unsigned)v_[size_-1], !=, 0, "Invalid representation");
    }
}

biguint::biguint(const char* s)
    : size_(0)
{
    auto slen = strlen(s);
    assert(slen);
    FUNTLS_CHECK_BINARY(slen, >, 0, "Empty string not allowed");

    FUNTLS_CHECK_BINARY((unsigned)s[0],==,'0',"Only hex supported");
    FUNTLS_CHECK_BINARY((unsigned)s[1],==,'x',"Only hex supported");

    FUNTLS_CHECK_BINARY(slen, >, 2, "Invalid hex string");
    std::string str(s+2, slen-2);
    if (str.size()%2) str.insert(str.begin(),'0');
    auto bytes = util::base16_decode(str);
    *this = from_be_bytes(bytes.data(), bytes.size());
    check_repr();
}

biguint biguint::from_be_bytes(const uint8_t* bytes, size_t size)
{
    FUNTLS_CHECK_BINARY(size, <=, max_bytes, "Out of representable range");
    biguint x;
    x.size_ = size;
    std::reverse_copy(bytes, bytes+size, x.v_);
    // trim
    while (x.size_ && !x.v_[x.size_-1]) {
        x.size_--;
    }
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

std::ostream& operator<<(std::ostream& os, const biguint& ui)
{
    ui.check_repr();
    if ((os.flags() & std::ios::basefield) != std::ios::hex) {
        // Ignore user whishes
        os << "0x";
    }
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
    return os;
}

} } // namespace funtls::bigint
