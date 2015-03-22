#ifndef TLS_H_INCLUDED
#define TLS_H_INCLUDED

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <cassert>
#include <type_traits>
#include <functional>
#include <vector>
#include <string>
#include <iostream>

namespace tls {

using uint8  = std::uint8_t;

template<unsigned BitCount>
struct uint {
    static_assert(BitCount >= 8, "");
    static_assert(BitCount % 8 == 0, "");

    uint(uint64_t value = 0) : value(value) {
        if (value >> BitCount) {
            throw std::logic_error(std::to_string(value) + " is out of range for uint<" + std::to_string(BitCount) + ">");
        }
    }

    operator uint64_t() const {
        return value;
    }

private:
    uint64_t value;
};

template<unsigned ByteCount>
struct opaque {
    uint8 data[ByteCount];
};

constexpr size_t log256(size_t n) {
    return n < 256 ? 1 : 1 + log256(n/256);
}

template<typename T, size_t LowerBoundInBytes, size_t UpperBoundInBytes>
struct vector {
    using serialized_size_type = uint<8*log256(UpperBoundInBytes)>;

    static_assert(LowerBoundInBytes < UpperBoundInBytes, "");
    static_assert(LowerBoundInBytes % sizeof(T) == 0, "");
    static_assert(UpperBoundInBytes % sizeof(T) == 0, "");

    constexpr vector() {
        static_assert(LowerBoundInBytes == 0, "");
    }

    vector(const std::vector<T>& l) : data(l) {
        const size_t byte_count = l.size() * sizeof(T);
        if (byte_count < LowerBoundInBytes || byte_count > UpperBoundInBytes) {
            throw std::logic_error("Byte count " + std::to_string(byte_count) + " is out of range [" 
                    + std::to_string(LowerBoundInBytes) + "; "
                    + std::to_string(UpperBoundInBytes)
                    + "] in " + __func__);
        }
    }

    vector(std::initializer_list<T> l) : vector(std::vector<T>{l}) {
    }

    template<unsigned size>
    vector(const T (&array)[size]) : data(&array[0], &array[size]) {
        static_assert(sizeof(array) >= LowerBoundInBytes, "");
        static_assert(sizeof(array) <= UpperBoundInBytes, "");
    }

    serialized_size_type byte_count() const {
        return data.size() * sizeof(T);
    }

    std::vector<T>  data;
};

enum class content_type : uint8_t {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

enum class handshake_type : uint8 {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange  = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20
};

struct protocol_version {
    uint8 major;
    uint8 minor;
};

constexpr bool operator==(const protocol_version& a, const protocol_version& b)
{
    return a.major == b.major && a.minor == b.minor;
}

constexpr bool operator!=(const protocol_version& a, const protocol_version& b)
{
    return !(a == b);
}

constexpr protocol_version protocol_version_tls_1_2{3, 3};

struct random {
    uint<32>   gmt_unix_time;
    opaque<28> random_bytes;
};
random make_random();

using session_id  = vector<uint8, 0, 32>;
session_id make_session_id();

using cipher_suite = opaque<2>; // Cryptographic suite selector
enum class compression_method : uint8 {
    null = 0
};

struct record {
    tls::content_type     content_type;
    tls::protocol_version protocol_version;
    tls::uint<16>         length;
};

struct client_hello {
    tls::protocol_version                               client_version;
    tls::random                                         random;
    tls::session_id                                     session_id;
    tls::vector<tls::cipher_suite, 2, (1<<16)-2>        cipher_suites;
    tls::vector<tls::compression_method, 1, (1<<8)-1>   compression_methods;
};

struct server_hello {
    tls::protocol_version   server_version;
    tls::random             random;
    tls::session_id         session_id;
    tls::cipher_suite       cipher_suite;
    tls::compression_method compression_method;
};

inline void append_to_buffer(std::vector<uint8_t>& buffer, uint8 item) {
    buffer.push_back(item);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, content_type item) {
    buffer.push_back(static_cast<uint8_t>(item));
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, compression_method item) {
    buffer.push_back(static_cast<uint8_t>(item));
}

template<unsigned BitCount>
inline void append_to_buffer(std::vector<uint8_t>& buffer, const uint<BitCount>& item) {
    const auto x = static_cast<uint64_t>(item);
    for (unsigned i = 0; i < BitCount/8; ++i) {
        buffer.push_back(x >> ((BitCount/8-1-i)*8));
    }
}

template<unsigned ByteCount>
inline void append_to_buffer(std::vector<uint8_t>& buffer, const opaque<ByteCount>& item) {
    buffer.insert(buffer.end(), item.data, item.data+ByteCount);
}

template<typename T, size_t LowerBoundInBytes, size_t UpperBoundInBytes>
inline void append_to_buffer(std::vector<uint8_t>& buffer, const vector<T, LowerBoundInBytes, UpperBoundInBytes>& item) {
    append_to_buffer(buffer, item.byte_count());
    for (const auto& subitem : item.data) {
        append_to_buffer(buffer, subitem);
    }
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const protocol_version& item) {
    buffer.push_back(item.major);
    buffer.push_back(item.minor);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const record& item) {
    append_to_buffer(buffer, item.content_type);
    append_to_buffer(buffer, item.protocol_version);
    append_to_buffer(buffer, item.length);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const random& item) {
    append_to_buffer(buffer, item.gmt_unix_time);
    append_to_buffer(buffer, item.random_bytes);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const client_hello& item) {
    append_to_buffer(buffer, item.client_version);
    append_to_buffer(buffer, item.random);
    append_to_buffer(buffer, item.session_id);
    append_to_buffer(buffer, item.cipher_suites);
    append_to_buffer(buffer, item.compression_methods);
}

template<unsigned BitCount>
inline void from_bytes(uint<BitCount>& item, const std::vector<uint8_t>& buffer, size_t& index) {
    if (index + BitCount/8 > buffer.size()) throw std::runtime_error("Out of data in " + std::string(__func__));
    uint64_t result = 0;
    for (unsigned i = 0; i < BitCount/8; ++i) {
        result |= static_cast<uint64_t>(buffer[index+i]) << ((BitCount/8-1-i)*8);
    }
    index += BitCount/8;
    item = uint<BitCount>(result);
}
inline void from_bytes(uint8_t& item, const std::vector<uint8_t>& buffer, size_t& index) {
    if (index + 1 > buffer.size()) throw std::runtime_error("Out of data in " + std::string(__func__));
    item = buffer[index++];
}
inline void from_bytes(handshake_type& item, const std::vector<uint8_t>& buffer, size_t& index) {
    if (index + 1 > buffer.size()) throw std::runtime_error("Out of data in " + std::string(__func__));
    item = static_cast<handshake_type>(buffer[index++]);
}
inline void from_bytes(content_type& item, const std::vector<uint8_t>& buffer, size_t& index) {
    if (index + 1 > buffer.size()) throw std::runtime_error("Out of data in " + std::string(__func__));
    item = static_cast<content_type>(buffer[index++]);
}
inline void from_bytes(compression_method& item, const std::vector<uint8_t>& buffer, size_t& index) {
    if (index + 1 > buffer.size()) throw std::runtime_error("Out of data in " + std::string(__func__));
    item = static_cast<compression_method>(buffer[index++]);
}
template<unsigned ByteCount>
inline void from_bytes(opaque<ByteCount>& item, const std::vector<uint8_t>& buffer, size_t& index) {
    if (index + ByteCount > buffer.size()) throw std::runtime_error("Out of data in " + std::string(__func__));
    for (unsigned i = 0; i < ByteCount; ++i) {
        item.data[i] = buffer[index++];
    }
}

template<typename T, size_t LowerBoundInBytes, size_t UpperBoundInBytes>
inline void from_bytes(vector<T, LowerBoundInBytes, UpperBoundInBytes>& item, const std::vector<uint8_t>& buffer, size_t& index) {
    uint<8*log256(UpperBoundInBytes)> byte_count;
    from_bytes(byte_count, buffer, index);
    if (byte_count < LowerBoundInBytes) throw std::runtime_error("Byte count " + std::to_string(byte_count) + " < " + std::to_string(LowerBoundInBytes));
    if (byte_count > UpperBoundInBytes) throw std::runtime_error("Byte count " + std::to_string(byte_count) + " > " + std::to_string(UpperBoundInBytes));
    if (byte_count % sizeof(T)) throw std::runtime_error("Byte count " + std::to_string(byte_count) + " % " + std::to_string(sizeof(T)));
    std::vector<T> data(byte_count / sizeof(T));
    for (auto& subitem : data) {
        from_bytes(subitem, buffer, index);
    }
    item = vector<T, LowerBoundInBytes, UpperBoundInBytes>{data};
}

inline void from_bytes(protocol_version& item, const std::vector<uint8_t>& buffer, size_t& index) {
    if (index + 2 > buffer.size()) throw std::runtime_error("Out of data in " + std::string(__func__));
    item.major = buffer[index++];
    item.minor = buffer[index++];
}
inline void from_bytes(random& item, const std::vector<uint8_t>& buffer, size_t& index) {
    from_bytes(item.gmt_unix_time, buffer, index);
    from_bytes(item.random_bytes, buffer, index);
}
inline void from_bytes(record& item, const std::vector<uint8_t>& buffer, size_t& index) {
    from_bytes(item.content_type, buffer, index);
    from_bytes(item.protocol_version, buffer, index);
    from_bytes(item.length, buffer, index);
}
inline void from_bytes(server_hello& item, const std::vector<uint8_t>& buffer, size_t& index) {
    from_bytes(item.server_version, buffer, index);
    from_bytes(item.random, buffer, index);
    from_bytes(item.session_id, buffer, index);
    from_bytes(item.cipher_suite, buffer, index);
    from_bytes(item.compression_method, buffer, index);
}

} // namespace tls


#endif
