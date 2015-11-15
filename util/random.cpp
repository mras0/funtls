#include "random.h"
#include <random>

namespace funtls { namespace util {

// TODO: FIXME: XXX: This isn't secure or smart
void get_random_bytes(void* dest, size_t count) {
	auto d = reinterpret_cast<uint8_t*>(dest);
    std::random_device rd{};
	while (count--) *d++ = static_cast<uint8_t>(rd());
}

} } // namespace funtls::util
