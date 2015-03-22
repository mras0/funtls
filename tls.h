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

#include "variant.h"

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

    size_t size() const {
        return data.size();
    }

    T operator[](size_t index) const {
        assert(index < size());
        return data[index];
    }
private:
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

struct client_hello {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::client_hello;

    tls::protocol_version                               client_version;
    tls::random                                         random;
    tls::session_id                                     session_id;
    tls::vector<tls::cipher_suite, 2, (1<<16)-2>        cipher_suites;
    tls::vector<tls::compression_method, 1, (1<<8)-1>   compression_methods;
};

struct server_hello {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::server_hello;

    tls::protocol_version   server_version;
    tls::random             random;
    tls::session_id         session_id;
    tls::cipher_suite       cipher_suite;
    tls::compression_method compression_method;
};

using asn1cert = tls::vector<tls::uint8, 1, (1<<24)-1>;

struct certificate {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::certificate;

    static constexpr size_t max_length = (1<<24)-1;

    //tls::vector<tls::asn1cert, 0, (1<<24)-1> certificate_list;
    std::vector<tls::asn1cert> certificate_list;
};

struct server_hello_done {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::server_hello_done;
};

struct handshake {
    static constexpr tls::content_type content_type = tls::content_type::handshake;

    tls::variant<client_hello, server_hello, certificate, server_hello_done> body;

    tls::handshake_type type() const {
        int type = -1;
        body.invoke(type_helper{type});
        assert(type >= 0 && type <= 255);
        return static_cast<tls::handshake_type>(type);
    }

private:
    struct type_helper {
        type_helper(int& type) : type(type) {}
        template<typename T>
        void operator()(const T&) {
            assert(type < 0);
            type = static_cast<int>(T::handshake_type);
            assert(type >= 0 && type <= 255);
        }
        int& type;
    };
};

struct record {
    static constexpr size_t max_length = (1<<14)-1;

    tls::protocol_version       protocol_version;
    tls::variant<handshake>     payload;

    tls::content_type type() const {
        int type = -1;
        payload.invoke(type_helper{type});
        assert(type >= 0 && type <= 255);
        return static_cast<tls::content_type>(type);
    }

private:
    struct type_helper {
        type_helper(int& type) : type(type) {}
        template<typename T>
        void operator()(const T&) {
            assert(type < 0);
            type = static_cast<int>(T::content_type);
            assert(type >= 0 && type <= 255);
        }
        int& type;
    };
};


inline void append_to_buffer(std::vector<uint8_t>& buffer, uint8 item) {
    buffer.push_back(item);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, handshake_type item) {
    buffer.push_back(static_cast<uint8_t>(item));
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
    for (size_t i = 0, sz = item.size(); i < sz; ++i) {
        append_to_buffer(buffer, item[i]);
    }
}

namespace detail {
struct append_helper {
    append_helper(std::vector<uint8_t>& buffer) : buffer(buffer) {
    }

    template<typename T>
    void operator()(const T& t) {
        append_to_buffer(buffer, t);
    }

    std::vector<uint8_t>& buffer;
};
} // namespace detail

template<typename... Ts>
void append_to_buffer(std::vector<uint8_t>& buffer, const tls::variant<Ts...>& item) {
    item.invoke(detail::append_helper{buffer});
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const protocol_version& item) {
    buffer.push_back(item.major);
    buffer.push_back(item.minor);
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

inline void append_to_buffer(std::vector<uint8_t>& buffer, const certificate& item) {
    (void) buffer; (void) item;
    assert(!"Not implemented");
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const server_hello& item) {
    (void) buffer; (void) item;
    assert(!"Not implemented");
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const server_hello_done& item) {
    (void) buffer; (void) item;
    assert(!"Not implemented");
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const handshake& item) {
    std::vector<uint8_t> body_buffer;
    append_to_buffer(body_buffer, item.body);

    append_to_buffer(buffer, item.type());
    append_to_buffer(buffer, tls::uint<24>{body_buffer.size()});
    buffer.insert(buffer.end(), body_buffer.begin(), body_buffer.end());
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const record& item) {
    std::vector<uint8_t> payload_buffer;
    append_to_buffer(payload_buffer, item.payload);

    assert(payload_buffer.size() < record::max_length);

    append_to_buffer(buffer, item.type());
    append_to_buffer(buffer, item.protocol_version);
    append_to_buffer(buffer, tls::uint<16>{payload_buffer.size()});
    buffer.insert(buffer.end(), payload_buffer.begin(), payload_buffer.end());
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
inline void from_bytes(server_hello& item, const std::vector<uint8_t>& buffer, size_t& index) {
    from_bytes(item.server_version, buffer, index);
    from_bytes(item.random, buffer, index);
    from_bytes(item.session_id, buffer, index);
    from_bytes(item.cipher_suite, buffer, index);
    from_bytes(item.compression_method, buffer, index);
}
inline void from_bytes(certificate& item, const std::vector<uint8_t>& buffer, size_t& index) {
    // TODO: XXX: This is ugly...
    uint<24> length;
    from_bytes(length, buffer, index);
    std::vector<tls::asn1cert> certificate_list;
    std::cout << "Reading " << length << " bytes of certificate data\n";
    if (index + length > buffer.size()) {
        throw std::runtime_error("Out of data in " + std::string(__func__));
    }
    size_t bytes_used = 3;
    for (;;) {
        uint<24> cert_length;
        from_bytes(cert_length, buffer, index);
        std::cout << " Found certificate of length " << cert_length << "\n";
        if (!cert_length) throw std::runtime_error("Empty certificate found");
        if (index + cert_length > buffer.size()) throw std::runtime_error("Out of data in " + std::string(__func__));
        std::vector<uint8> cert_data(&buffer[index], &buffer[index+cert_length]);
        index+=cert_length;
        certificate_list.emplace_back(std::move(cert_data));
        bytes_used+=cert_length;
        if (bytes_used >= length) {
            assert(bytes_used == length);
            break;
        }
    }
    item.certificate_list = std::move(certificate_list);
}

} // namespace tls


#endif
