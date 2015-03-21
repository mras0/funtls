#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
#include <cassert>
#include <type_traits>
#include <functional>

#include <sys/time.h> // gettimeofday

#include <boost/asio.hpp>

// http://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl
// openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
// cat server_key.pem server_cert.pem >server.pem
// openssl s_server

char hexchar(uint8_t d)
{
    assert(d < 16);
    return d < 10 ? d + '0' : d + 'a' - 10;
}

std::string hexstring(const void* buffer, size_t len)
{
    const uint8_t* bytes = static_cast<const uint8_t*>(buffer);
    assert(len <= len*2);
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += hexchar(bytes[i] >> 4);
        result += hexchar(bytes[i] & 0xf);
    }
    return result;
}

template<typename T>
std::string hexstring(const T& x)
{
    if (x.empty()) return "";
    return hexstring(&x[0], x.size() * sizeof(x[0]));
}

namespace tls {

namespace detail {
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

} // namespace detail

using uint8  = std::uint8_t;

template<unsigned BitCount>
struct uint {
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
    uint8 data[BitCount/8];

    template<typename F>
    void for_each_member(F f) const {
        for (const auto& d : data) {
            f(d);
        }
    }
};

template<unsigned ByteCount>
struct opaque {
    uint8 data[ByteCount];

    template<typename F>
    void for_each_member(F f) const {
        for (const auto& d : data) {
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

    constexpr vector() {
        static_assert(LowerBoundInBytes == 0, "");
    }

    vector(std::initializer_list<T> l) : data(l) {
        // Would be nice if these checks could be static_asserts as well
        if (l.size() < LowerBoundInBytes/sizeof(T) || l.size() > UpperBoundInBytes/sizeof(T)) {
            throw std::logic_error(std::to_string(l.size()) + " is out of range [" 
                    + std::to_string(LowerBoundInBytes/sizeof(T)) + "; "
                    + std::to_string(l.size() <= UpperBoundInBytes/sizeof(T))
                    + "]");
        }

    }

    template<unsigned size>
    vector(const T (&array)[size]) : data(&array[0], &array[size]) {
        static_assert(sizeof(array) >= LowerBoundInBytes, "");
        static_assert(sizeof(array) <= UpperBoundInBytes, "");
    }

    template<typename F>
    void for_each_member(F f) const {
        f(uint<8*log256(UpperBoundInBytes)>(sizeof(T)*data.size())); // size
        for (const auto& item : data) {
            f(item);
        }
    }

private:
    std::vector<T> data;
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
    void for_each_member(F f) const {
        f(major);
        f(minor);
    }
};

constexpr protocol_version protocol_version_tls_1_2{3, 3};

struct random {
    uint<32>   gmt_unix_time;
    opaque<28> random_bytes;

    template<typename F>
    void for_each_member(F f) const {
        f(gmt_unix_time);
        f(random_bytes);
    }
};

inline random make_random() {
    random r;
    r.gmt_unix_time = detail::get_gmt_unix_time();
    detail::get_random_bytes(r.random_bytes);
    return r;
}

using session_id  = vector<uint8, 0, 32>;

session_id make_session_id()
{
    uint8_t buffer[16];
    detail::get_random_bytes(buffer);
    return {buffer};
}

using cipher_suite = opaque<2>; // Cryptographic suite selector
constexpr cipher_suite null_with_null_null             = { 0x00,0x00 };

constexpr cipher_suite rsa_with_null_md5               = { 0x00,0x01 };
constexpr cipher_suite rsa_with_null_sha               = { 0x00,0x02 };
constexpr cipher_suite rsa_with_null_sha256            = { 0x00,0x3B };
constexpr cipher_suite rsa_with_rc4_128_md5            = { 0x00,0x04 };
constexpr cipher_suite rsa_with_rc4_128_sha            = { 0x00,0x05 };
constexpr cipher_suite rsa_with_3des_ede_cbc_sha       = { 0x00,0x0A };
constexpr cipher_suite rsa_with_aes_128_cbc_sha        = { 0x00,0x2F };
constexpr cipher_suite rsa_with_aes_256_cbc_sha        = { 0x00,0x35 };
constexpr cipher_suite rsa_with_aes_128_cbc_sha256     = { 0x00,0x3C };
constexpr cipher_suite rsa_with_aes_256_cbc_sha256     = { 0x00,0x3D };

constexpr cipher_suite dh_dss_with_3des_ede_cbc_sha    = { 0x00,0x0D };
constexpr cipher_suite dh_rsa_with_3des_ede_cbc_sha    = { 0x00,0x10 };
constexpr cipher_suite dhe_dss_with_3des_ede_cbc_sha   = { 0x00,0x13 };
constexpr cipher_suite dhe_rsa_with_3des_ede_cbc_sha   = { 0x00,0x16 };
constexpr cipher_suite dh_dss_with_aes_128_cbc_sha     = { 0x00,0x30 };
constexpr cipher_suite dh_rsa_with_aes_128_cbc_sha     = { 0x00,0x31 };
constexpr cipher_suite dhe_dss_with_aes_128_cbc_sha    = { 0x00,0x32 };
constexpr cipher_suite dhe_rsa_with_aes_128_cbc_sha    = { 0x00,0x33 };
constexpr cipher_suite dh_dss_with_aes_256_cbc_sha     = { 0x00,0x36 };
constexpr cipher_suite dh_rsa_with_aes_256_cbc_sha     = { 0x00,0x37 };
constexpr cipher_suite dhe_dss_with_aes_256_cbc_sha    = { 0x00,0x38 };
constexpr cipher_suite dhe_rsa_with_aes_256_cbc_sha    = { 0x00,0x39 };
constexpr cipher_suite dh_dss_with_aes_128_cbc_sha256  = { 0x00,0x3E };
constexpr cipher_suite dh_rsa_with_aes_128_cbc_sha256  = { 0x00,0x3F };
constexpr cipher_suite dhe_dss_with_aes_128_cbc_sha256 = { 0x00,0x40 };
constexpr cipher_suite dhe_rsa_with_aes_128_cbc_sha256 = { 0x00,0x67 };
constexpr cipher_suite dh_dss_with_aes_256_cbc_sha256  = { 0x00,0x68 };
constexpr cipher_suite dh_rsa_with_aes_256_cbc_sha256  = { 0x00,0x69 };
constexpr cipher_suite dhe_dss_with_aes_256_cbc_sha256 = { 0x00,0x6A };
constexpr cipher_suite dhe_rsa_with_aes_256_cbc_sha256 = { 0x00,0x6B };

constexpr cipher_suite dh_anon_with_rc4_128_md5        = { 0x00,0x18 };
constexpr cipher_suite dh_anon_with_3des_ede_cbc_sha   = { 0x00,0x1B };
constexpr cipher_suite dh_anon_with_aes_128_cbc_sha    = { 0x00,0x34 };
constexpr cipher_suite dh_anon_with_aes_256_cbc_sha    = { 0x00,0x3A };
constexpr cipher_suite dh_anon_with_aes_128_cbc_sha256 = { 0x00,0x6C };
constexpr cipher_suite dh_anon_with_aes_256_cbc_sha256 = { 0x00,0x6D };

enum class compression_method : uint8 {
    null = 0
};

struct client_hello {
    tls::protocol_version                               client_version;
    tls::random                                         random;
    tls::session_id                                     session_id;
    tls::vector<tls::cipher_suite, 2, (1<<16)-2>        cipher_suites;
    tls::vector<tls::compression_method, 1, (1<<8)-1>   compression_methods;

    template<typename F>
    void for_each_member(F f) const {
        f(client_version);
        f(random);
        f(session_id);
        f(cipher_suites);
        f(compression_methods);
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
        item.for_each_member(appender{buffer});
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
        item.for_each_member(sizer{sz});
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

} // namespace tls

#if 0

struct {
    ProtocolVersion client_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suites<2..2^16-2>;
    CompressionMethod compression_methods<1..2^8-1>;
    select (extensions_present) {
        case false:
            struct {};
        case true:
            Extension extensions<0..2^16-1>;
    };
} ClientHello;

struct {
    HandshakeType msg_type;    /* handshake type */
    uint24 length;             /* bytes in message */
    select (HandshakeType) {
        case hello_request:       HelloRequest;
        case client_hello:        ClientHello;
        case server_hello:        ServerHello;
        case certificate:         Certificate;
        case server_key_exchange: ServerKeyExchange;
        case certificate_request: CertificateRequest;
        case server_hello_done:   ServerHelloDone;
        case certificate_verify:  CertificateVerify;
        case client_key_exchange: ClientKeyExchange;
        case finished:            Finished;
    } body;
} Handshake;
#endif

void ClientHello(boost::asio::ip::tcp::socket& socket)
{
    std::vector<uint8_t> buffer;
    tls::client_hello body{
        tls::protocol_version_tls_1_2,
        tls::make_random(),
        tls::make_session_id(),
        { tls::rsa_with_aes_256_cbc_sha256 },
        { tls::compression_method::null },
    };

    auto body_size = tls::size(body);
    // Record header
    tls::append_to_buffer(buffer, tls::content_type::handshake);
    tls::append_to_buffer(buffer, tls::protocol_version_tls_1_2);
    tls::append_to_buffer(buffer, tls::uint<16>(body_size + 4));
    assert(buffer.size() == 5);
    // Handshake header
    tls::append_to_buffer(buffer, tls::handshake_type::client_hello);
    tls::append_to_buffer(buffer, tls::uint<24>(body_size));
    tls::append_to_buffer(buffer, body);
    assert(buffer.size() == 5 + 4 + body_size);
    boost::asio::write(socket, boost::asio::buffer(buffer));
}

int main()
{
    const char* const host = "localhost";
    const char* const port = "4433";

    try {
        boost::asio::io_service         io_service;
        boost::asio::ip::tcp::socket    socket(io_service);
        boost::asio::ip::tcp::resolver  resolver(io_service);

        std::cout << "Connecting to " << host << ":" << port << " ..." << std::flush;
        boost::asio::connect(socket, resolver.resolve({host, port}));
        std::cout << " OK" << std::endl;
        /*
        Client                                               Server

        ClientHello                  -------->
                                                        ServerHello
                                                       Certificate*
                                                 ServerKeyExchange*
                                                CertificateRequest*
                                     <--------      ServerHelloDone
        Certificate*
        ClientKeyExchange
        CertificateVerify*
        [ChangeCipherSpec]
        Finished                     -------->
                                                 [ChangeCipherSpec]
                                     <--------             Finished
        Application Data             <------->     Application Data
        */

        std::cout << "Sending ClientHello ..." << std::flush;
        ClientHello(socket);
        std::cout << " OK" << std::endl;

        std::vector<uint8_t> buffer;
        buffer.resize(1024);

        size_t byte_count = socket.read_some(boost::asio::buffer(buffer));
        std::cout << byte_count << " bytes read:\n";
        std::cout << hexstring(buffer) << std::endl;


    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Caught unknown exception" << std::endl;
        return 1;
    }
    return 0;
}
