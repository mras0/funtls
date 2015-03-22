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
    uint() : data() {}
    uint(uint64_t x) {
        if (x >> BitCount) {
            throw std::logic_error(std::to_string(x) + " is out of range for uint<" + std::to_string(BitCount) + ">");
        }
        for (unsigned i = 0; i < BitCount/8; ++i) {
            data[i] = x >> ((BitCount/8-1-i)*8);
        }
    }

    operator uint64_t() const {
        uint64_t result = 0;
        for (unsigned i = 0; i < BitCount/8; ++i) {
            result |= static_cast<uint64_t>(data[i]) << ((BitCount/8-1-i)*8);
        }
        return result;
    }

    uint8 data[BitCount/8];

    template<typename F>
    void for_each_member(F f) {
        for (auto& d : data) {
            f(d);
        }
    }
};

template<unsigned ByteCount>
struct opaque {
    uint8 data[ByteCount];

    template<typename F>
    void for_each_member(F f) {
        for (auto& d : data) {
            f(d);
        }
    }
};

constexpr size_t log256(size_t n) {
    return n < 256 ? 1 : 1 + log256(n/256);
}

template<typename T, size_t LowerBoundInBytes, size_t UpperBoundInBytes>
struct vector {
    static_assert(LowerBoundInBytes < UpperBoundInBytes, "");
    static_assert(LowerBoundInBytes % sizeof(T) == 0, "");
    static_assert(UpperBoundInBytes % sizeof(T) == 0, "");

    constexpr vector() : byte_count(0) {
        static_assert(LowerBoundInBytes == 0, "");
    }

    vector(std::initializer_list<T> l) : byte_count(l.size()*sizeof(T)), data(l) {
        // Would be nice if these checks could be static_asserts as well
        if (byte_count < LowerBoundInBytes || byte_count > UpperBoundInBytes) {
            throw std::logic_error("Byte count " + std::to_string(byte_count) + " is out of range [" 
                    + std::to_string(LowerBoundInBytes) + "; "
                    + std::to_string(UpperBoundInBytes)
                    + "] in " + __func__);
        }

    }

    template<unsigned size>
    vector(const T (&array)[size]) : byte_count(sizeof(array)), data(&array[0], &array[size]) {
        static_assert(sizeof(array) >= LowerBoundInBytes, "");
        static_assert(sizeof(array) <= UpperBoundInBytes, "");
    }

    template<typename F>
    void for_each_member(F f) {
        f(byte_count);
        if (byte_count != sizeof(T) * data.size()) {
            std::cerr << "\nUGLY STUFF IN " << __FILE__ << ":" << __LINE__ << " " << __func__ << std::endl;
            assert(data.empty());
            assert(byte_count % sizeof(T) == 0);
            data.resize(byte_count/sizeof(T));
        }
        for (auto& item : data) {
            f(item);
        }
    }

private:
    uint<8*log256(UpperBoundInBytes)> byte_count;
    std::vector<T>                    data;
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

    template<typename F>
    void for_each_member(F f) {
        f(major);
        f(minor);
    }
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

    template<typename F>
    void for_each_member(F f) {
        f(gmt_unix_time);
        f(random_bytes);
    }
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
    template<typename F>
    void for_each_member(F f) {
        f(content_type);
        f(protocol_version);
        f(length);
    }
};

struct client_hello {
    tls::protocol_version                               client_version;
    tls::random                                         random;
    tls::session_id                                     session_id;
    tls::vector<tls::cipher_suite, 2, (1<<16)-2>        cipher_suites;
    tls::vector<tls::compression_method, 1, (1<<8)-1>   compression_methods;

    template<typename F>
    void for_each_member(F f) {
        f(client_version);
        f(random);
        f(session_id);
        f(cipher_suites);
        f(compression_methods);
    }
};

struct server_hello {
    tls::protocol_version   server_version;
    tls::random             random;
    tls::session_id         session_id;
    tls::cipher_suite       cipher_suite;
    tls::compression_method compression_method;

    template<typename F>
    void for_each_member(F f) {
        f(server_version);
        f(random);
        f(session_id);
        f(cipher_suite);
        f(compression_method);
    }
};

namespace detail {

// http://en.wikibooks.org/wiki/More_C++_Idioms/Member_Detector
template<typename T, typename U=void>
struct has_for_each_member {
    static constexpr bool value = false;
};

template<typename T>
struct has_for_each_member<T, typename std::enable_if<std::is_class<T>::value>::type> {
private:
    struct fallback { int for_each_member; };
    struct derived : T, fallback {};
    using no  = char[1];
    using yes = char[2];
    template<typename U> static no&  test(decltype(U::for_each_member)*);
    template<typename U> static yes& test(U*);
public:
    static constexpr bool value = sizeof(test<derived>(nullptr)) == sizeof(yes);
};

static_assert(has_for_each_member<uint<16>>::value, "");

template<typename T>
struct append_helper {
   template<typename U=T>
    static void append(std::vector<uint8_t>& buffer, const T& item, typename std::enable_if<!has_for_each_member<U>::value>::type* = 0) {
        static_assert(std::is_pod<T>::value, "");
        auto first = reinterpret_cast<const uint8_t*>(&item);
        auto last  = first + sizeof(T);
        buffer.insert(buffer.end(), first, last);
    }
    template<typename U=T>
    static void append(std::vector<uint8_t>& buffer, const T& item, typename std::enable_if<has_for_each_member<U>::value>::type* = 0) {
        const_cast<T&>(item).for_each_member(appender{buffer});
    }
private:
    struct appender {
        appender(std::vector<uint8_t>& buffer) : buffer(buffer) {}
        template<typename MemberItemType>
        void operator()(const MemberItemType& member_item) {
            append_helper<MemberItemType>::append(buffer, member_item);
        }
        std::vector<uint8_t>& buffer;
    };
};

template<typename T>
struct size_helper {
   template<typename U=T>
    static void size(size_t& sz, const T&, typename std::enable_if<!has_for_each_member<U>::value>::type* = 0) {
        static_assert(std::is_pod<T>::value, "");
        sz += sizeof(T);
    }
    template<typename U=T>
    static void size(size_t& sz, const T& item, typename std::enable_if<has_for_each_member<U>::value>::type* = 0) {
        const_cast<T&>(item).for_each_member(sizer{sz});
    }
private:
    struct sizer {
        sizer(size_t& sz) : sz(sz) {}
        template<typename MemberItemType>
        void operator()(const MemberItemType& member_item) {
            size_helper<MemberItemType>::size(sz, member_item);
        }
        size_t& sz;
    };
};

template<typename T>
struct from_bytes_helper {
   template<typename U=T>
    static void from_bytes(T& item, const uint8_t* buffer, size_t buffer_size, size_t& index, typename std::enable_if<!has_for_each_member<U>::value>::type* = 0) {
        static_assert(std::is_pod<T>::value, "");
        if (index + sizeof(T) > buffer_size) {
            assert(false);
            throw std::runtime_error("Too few bytes available in " + std::string(__func__));
        }
        memcpy(&item, &buffer[index], sizeof(T));
        index += sizeof(T);
    }
    template<typename U=T>
    static void from_bytes(T& item, const uint8_t* buffer, size_t buffer_size, size_t& index, typename std::enable_if<has_for_each_member<U>::value>::type* = 0) {
        item.for_each_member(iter_helper{buffer,buffer_size,index});
    }
private:
    struct iter_helper {
        iter_helper(const uint8_t* buffer, size_t buffer_size, size_t& index) : buffer(buffer), buffer_size(buffer_size), index(index) {}
        template<typename MemberItemType>
        void operator()(MemberItemType& member_item) {
            from_bytes_helper<MemberItemType>::from_bytes(member_item, buffer, buffer_size, index);
        }
        const uint8_t* buffer;
        size_t         buffer_size;
        size_t&        index;
    };
};

} // namespace detail

template<typename T>
void append_to_buffer(std::vector<uint8_t>& buffer, const T& item) {
    detail::append_helper<T>::append(buffer, item);
}

template<typename T>
size_t size(const T& item) {
    size_t sz = 0;
    detail::size_helper<T>::size(sz, item);
    return sz;
}

template<typename T>
void from_bytes(T& item, const std::vector<uint8_t>& buffer, size_t& index)
{
    assert(!buffer.empty());
    detail::from_bytes_helper<T>::from_bytes(item, &buffer[0], buffer.size(), index);
}

} // namespace tls


#endif
