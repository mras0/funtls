#include "random.h"
#include <fstream>
#include <stdexcept>

#ifdef WIN32
#include <random>
#endif

namespace funtls { namespace util {

void get_random_bytes(void* dest, size_t count) {
#ifdef WIN32
	auto d = reinterpret_cast<uint8_t*>(dest);
	while (count--) *d++ = static_cast<uint8_t>(std::random_device()());
#elif 1
    std::ifstream urandom("/dev/urandom", std::ifstream::binary);
    if (!urandom || !urandom.is_open()) {
        throw std::runtime_error("Could not open /dev/urandom");
    }
    if (!urandom.read(reinterpret_cast<char*>(dest), count)) {
        throw std::runtime_error("Could not read from /dev/urandom");
    }
#else
    // "random" but reproducable results
    static uint8_t seed = 0;
    uint8_t* b = static_cast<uint8_t*>(dest);
    while (count--) {
        *b++ = seed++;
    }
#endif
}

} } // namespace funtls::util
