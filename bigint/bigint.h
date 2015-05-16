#ifndef FUNTLS_BIGINT_BIGINT_H_INCLUDED
#define FUNTLS_BIGINT_BIGINT_H_INCLUDED

#include <cassert>
#include <stdint.h>
#include <iosfwd>

namespace funtls { namespace bigint {

class biguint {
public:
    static constexpr size_t max_bytes = 4096;
    static constexpr size_t max_bits  = 8 * max_bytes;

    biguint() : size_(0) {
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

    static biguint from_be_bytes(const uint8_t* bytes, size_t size);

    friend bool operator==(const biguint& lhs, const biguint& rhs);
    friend std::ostream& operator<<(std::ostream& os, const biguint& ui);

private:
    uint16_t size_;
    uint8_t  v_[max_bytes];

    void check_repr() const;
};

inline bool operator!=(const biguint& lhs, const biguint& rhs) {
    return !(lhs == rhs);
}

} } // namespace funtls::bigint

#endif


