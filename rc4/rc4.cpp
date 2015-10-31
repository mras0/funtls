#include "rc4.h"
#include <cassert>
#include <algorithm>
#include <util/test.h>

namespace funtls { namespace rc4 {

rc4::rc4(const std::vector<uint8_t>& key)
    : i(0)
    , j(0)
{
    FUNTLS_CHECK_BINARY(key.size(), !=, 0, "Empty key not allowed");
    for (unsigned n = 0; n < 256; ++n) {
        S[n] = static_cast<uint8_t>(n);
    }
    j = 0;
    do {
        j = j + S[i] + key[i % key.size()];
        std::swap(S[i], S[j]);
    } while (i++ != 255);
    i = j = 0;
}

rc4& rc4::process(std::vector<uint8_t>& data)
{
    for (auto& b : data) {
        ++i;
        j = j + S[i];
        std::swap(S[i], S[j]);
        const uint8_t K = S[uint8_t(S[i] + S[j])];
        b ^= K;
    }
    return *this;
}

} } // namespace funtls::rc4
