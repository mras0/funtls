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

uint8    uint_from_bytes(uint8_t b0) { return b0; }
uint<16> uint_from_bytes(uint8_t b0, uint8_t b1) { return (static_cast<uint64_t>(b0)<<8)|b1; }

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

std::pair<tls::content_type, std::vector<uint8_t>> read_record(boost::asio::ip::tcp::socket& socket)
{
    std::vector<uint8_t> buffer(5);
    boost::asio::read(socket, boost::asio::buffer(buffer));

    tls::record record;
    size_t index = 0;
    tls::from_bytes(record, buffer, index);
    assert(index == buffer.size());

    if (record.protocol_version != tls::protocol_version_tls_1_2) {
        throw std::runtime_error("Invalid record protocol version " + hexstring(&record.protocol_version, sizeof(record.protocol_version)) + " in " + __func__);
    }
    const size_t max_length = (1<<14)-1;
    if (record.length < 1 || record.length > max_length) {
        throw std::runtime_error("Invalid record length " + std::to_string(record.length) + " in " + __func__);
    }
    buffer.resize(record.length);
    boost::asio::read(socket, boost::asio::buffer(buffer));

    return std::make_pair(record.content_type, std::move(buffer));
}

std::pair<tls::handshake_type, std::vector<uint8_t>> read_handshake(boost::asio::ip::tcp::socket& socket)
{
    auto record = read_record(socket);
    if (record.first != tls::content_type::handshake) {
        throw std::runtime_error("Invalid record content type " + hexstring(&record.first, sizeof(record.first)) + " in " + __func__);
    }

    size_t index = 0;
    tls::handshake_type handshake_type;
    tls::uint<24> body_size;
    tls::from_bytes(handshake_type, record.second, index);
    tls::from_bytes(body_size, record.second, index);
    if (index + body_size > record.second.size()) {
        throw std::runtime_error("Invalid body size " + std::to_string(body_size));
    }
    return std::make_pair(handshake_type, std::vector<uint8_t>{record.second.begin() + index, record.second.end()});
 }

void HandleServerHello(boost::asio::ip::tcp::socket& socket)
{
    auto handshake = read_handshake(socket);
    tls::server_hello server_hello;
    size_t index = 0;
    tls::from_bytes(server_hello, handshake.second, index);
    assert(index == handshake.second.size());
    if (handshake.first != tls::handshake_type::server_hello) {
        throw std::runtime_error("Invalid handshake type " + hexstring(&handshake.first, sizeof(handshake.first)) + " in " + __func__);
    }
    std::cout << "Cipher: "      << hexstring(&server_hello.cipher_suite, 2) << std::endl;
    std::cout << "Compresison: " << (int)server_hello.compression_method << std::endl;

    for (;;) {
        auto handshake = read_handshake(socket);
        std::cout << "Got handshake: " << hexstring(&handshake.first, sizeof(handshake.first)) << std::endl;
        if (handshake.first == tls::handshake_type::server_hello_done) break;
    }
}

void SendClientHello(boost::asio::ip::tcp::socket& socket)
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
    tls::record record {
        tls::content_type::handshake,
        tls::protocol_version_tls_1_2,
        tls::uint<16>(body_size + 4)
    };
    tls::append_to_buffer(buffer, record);
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
        SendClientHello(socket);
        std::cout << " OK" << std::endl;

        std::cout << "Handling ServerHello ..." << std::flush;
        HandleServerHello(socket);
        std::cout << " OK" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Caught unknown exception" << std::endl;
        return 1;
    }
    return 0;
}
