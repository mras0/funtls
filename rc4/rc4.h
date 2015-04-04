#ifndef FUNTLS_RC4_RC4_H_INCLUDED
#define FUNTLS_RC4_RC4_H_INCLUDED

#include <cstdint>
#include <vector>

namespace funtls { namespace rc4 {

class rc4 {
public:
    rc4(const std::vector<uint8_t>& key);
    rc4& process(std::vector<uint8_t>& data);
private:

    uint8_t S[256];
    uint8_t i, j;
};

} } // namespace funtls::rc4

#endif
