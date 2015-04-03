#include "tls.h"
#include <util/base_conversion.h>
#include <sys/time.h> // gettimeofday

namespace {
template<typename T>
void get_random_bytes(T& t) {
    static_assert(std::is_pod<T>::value && !std::is_pointer<T>::value, "");
    funtls::tls::get_random_bytes(&t, sizeof(T));
}

uint32_t get_gmt_unix_time()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return static_cast<uint32_t>(tv.tv_sec);
}

} // unnamed namespace

namespace funtls { namespace tls {

// "random"
void get_random_bytes(void* dest, size_t count) {
    static uint8_t seed = 0;
    uint8_t* b = static_cast<uint8_t*>(dest);
    while (count--) {
        *b++ = seed++;
    }
}

random make_random() {
    random r;
    r.gmt_unix_time = get_gmt_unix_time();
    ::get_random_bytes(r.random_bytes);
    return r;
}

std::vector<uint8_t> random::as_vector() const {
    std::vector<uint8_t> buf;
    append_to_buffer(buf, *this);
    return buf;
}

handshake handshake_from_bytes(const std::vector<uint8_t>& buffer, size_t& index)
{
    tls::handshake_type handshake_type;
    tls::uint24 body_size;
    tls::from_bytes(handshake_type, buffer, index);
    tls::from_bytes(body_size, buffer, index);
    if (index + body_size > buffer.size()) {
        throw std::runtime_error("Invalid body size " + std::to_string(body_size));
    }
    if (handshake_type == tls::handshake_type::server_hello) {
        tls::server_hello server_hello;
        tls::from_bytes(server_hello, buffer, index);
        assert(index == buffer.size());
        return tls::handshake{std::move(server_hello)};
    } else if (handshake_type == tls::handshake_type::certificate) {
        tls::certificate certificate;
        tls::from_bytes(certificate, buffer, index);
        assert(index == buffer.size());
        return tls::handshake{std::move(certificate)};
    } else if (handshake_type == tls::handshake_type::server_hello_done) {
        if (body_size != 0) {
            throw std::runtime_error("Got body " + std::to_string(body_size) + " for server_hello_done");
        }
        assert(index == buffer.size());
        return tls::handshake{tls::server_hello_done{}};
    }
    throw std::runtime_error("Unknown handshake type " + std::to_string((int)handshake_type));
}

std::ostream& operator<<(std::ostream& os, const content_type& type)
{
    switch (type) {
        case content_type::change_cipher_spec:
            return os << "change_cipher_spec";
        case content_type::alert:
            return os << "alert";
        case content_type::handshake:
            return os << "handshake";
        case content_type::application_data:
            return os << "application_data";
    }
    os << "Unknown TLS content type 0x" << util::base16_encode(&type, sizeof(type));
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, const protocol_version& version)
{
    if (version == protocol_version_tls_1_0) {
        os << "TLS v1.0";
    } else if (version == protocol_version_tls_1_1) {
        os << "TLS v1.1";
    } else if (version == protocol_version_tls_1_2) {
        os << "TLS v1.2";
    } else {
        os << "Unknown TLS version " << version.major << "." << version.minor;
        assert(false);
    }
    return os;
}

} } // namespace funtls::tls
