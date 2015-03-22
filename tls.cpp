#include "tls.h"

#include <sys/time.h> // gettimeofday

namespace {
// "random"
void get_random_bytes(void* dest, size_t count) {
    static uint8_t seed = 0;
    uint8_t* b = static_cast<uint8_t*>(dest);
    while (count--) {
        *b++ = seed++;
    }
}
template<typename T>
void get_random_bytes(T& t) {
    static_assert(std::is_pod<T>::value && !std::is_pointer<T>::value, "");
    get_random_bytes(&t, sizeof(T));
}

uint32_t get_gmt_unix_time()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint32_t>(tv.tv_sec);
}

} // unnamed namespace

namespace tls {
namespace detail {
} // namespace detail

random make_random() {
    random r;
    r.gmt_unix_time = get_gmt_unix_time();
    get_random_bytes(r.random_bytes);
    return r;
}

session_id make_session_id()
{
    uint8_t buffer[16];
    get_random_bytes(buffer);
    return {buffer};
}


} // namespace tls
