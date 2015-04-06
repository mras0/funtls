#ifndef FUNTLS_3DES_3DES_H_INCLUDED
#define FUNTLS_3DES_3DES_H_INCLUDED

#include <cstdint>
#include <vector>

// 3DES - http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf

namespace funtls { namespace _3des {
static constexpr uint8_t key_length_bytes    = 192/8;
static constexpr uint8_t block_length_bytes  = 64/8;
} } // namespace funtls::_3des


#endif
