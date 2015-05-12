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

#include <util/buffer.h>

#include <tls/tls_ciphers.h>

namespace funtls { namespace tls {

static constexpr size_t master_secret_size = 48;

template<unsigned BitCount, typename Underlying>
struct uint {
    static_assert(BitCount >= 8, "");
    static_assert(BitCount % 8 == 0, "");
    static_assert(sizeof(Underlying) * 8 > BitCount, "");

    static constexpr Underlying max_size = Underlying{1} << BitCount;

    uint(Underlying value = 0) : value(value) {
        if (value >> BitCount) {
            throw std::logic_error(std::to_string(value) + " is out of range for uint<" + std::to_string(BitCount) + ">");
        }
    }

    operator Underlying() const {
        assert(value < max_size);
        return value;
    }

private:
    Underlying value;
};

using uint8  = uint8_t;
using uint16 = uint16_t;
using uint24 = uint<24, uint32_t>;
using uint32 = uint32_t;
using uint64 = uint64_t;

template<unsigned BitCount>
struct smallest_possible_uint;

template<> struct smallest_possible_uint<8> { using type = uint8; };
template<> struct smallest_possible_uint<16> { using type = uint16; };
template<> struct smallest_possible_uint<24> { using type = uint24; };
template<> struct smallest_possible_uint<32> { using type = uint32; };
template<> struct smallest_possible_uint<64> { using type = uint64; };

enum class content_type : uint8_t {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};
std::ostream& operator<<(std::ostream& os, content_type type);

enum class alert_level : uint8_t {
    warning = 1,
    fatal = 2
};
std::ostream& operator<<(std::ostream& os, alert_level level);

enum class alert_description : uint8_t {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed_RESERVED = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate_RESERVED = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction_RESERVED = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    user_canceled = 90,
    no_renegotiation = 100,
    unsupported_extension = 110,
};
std::ostream& operator<<(std::ostream& os, alert_description desc);

struct alert {
    static constexpr tls::content_type content_type = tls::content_type::alert;

    alert_level       level;
    alert_description description;
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

static_assert(sizeof(protocol_version) == 2, "");

constexpr bool operator==(const protocol_version& a, const protocol_version& b) {
    return a.major == b.major && a.minor == b.minor;
}

constexpr bool operator!=(const protocol_version& a, const protocol_version& b) {
    return !(a == b);
}

std::ostream& operator<<(std::ostream& os, const protocol_version& version);

static constexpr protocol_version protocol_version_tls_1_0{3, 1};
static constexpr protocol_version protocol_version_tls_1_1{3, 2};
static constexpr protocol_version protocol_version_tls_1_2{3, 3};

constexpr size_t log256(size_t n) {
    return n < 256 ? 1 : 1 + log256(n/256);
}

template<typename T, size_t LowerBoundInBytes, size_t UpperBoundInBytes>
struct vector {
    using serialized_size_type = typename smallest_possible_uint<8*log256(UpperBoundInBytes)>::type;

    static_assert(LowerBoundInBytes < UpperBoundInBytes, "");
    static_assert(LowerBoundInBytes % sizeof(T) == 0, "");
    static_assert(UpperBoundInBytes % sizeof(T) == 0, "");

    constexpr vector() {
        //static_assert(LowerBoundInBytes == 0, "");
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

    const std::vector<T>& as_vector() const {
        return data;
    }

private:
    std::vector<T>  data;
};

struct random {
    uint32   gmt_unix_time;
    uint8    random_bytes[28];

    std::vector<uint8_t> as_vector() const;
};
random make_random();

using session_id  = vector<uint8, 0, 32>;

enum class compression_method : uint8 {
    null = 0
};

struct extension {
    enum extension_type : uint16_t {
        elliptic_curves      = 10,
        ec_point_formats     = 11,
        signature_algorithms = 13,
    };

    extension_type                   type;
    tls::vector<uint8, 0, (1<<16)-1> data;
};

std::ostream& operator<<(std::ostream& os, extension::extension_type etype);

struct client_hello {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::client_hello;

    tls::protocol_version                               client_version;
    tls::random                                         random;
    tls::session_id                                     session_id;
    tls::vector<tls::cipher_suite, 2, (1<<16)-2>        cipher_suites;
    tls::vector<tls::compression_method, 1, (1<<8)-1>   compression_methods;
    std::vector<extension>                              extensions; //<0..2^16-1>;
};

struct server_hello {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::server_hello;

    tls::protocol_version   server_version;
    tls::random             random;
    tls::session_id         session_id;
    tls::cipher_suite       cipher_suite;
    tls::compression_method compression_method;
    std::vector<extension>  extensions; //<0..2^16-1>;
};

using asn1cert = tls::vector<tls::uint8, 1, (1<<24)-1>;

struct certificate {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::certificate;

    static constexpr size_t max_length = (1<<24)-1;

    //tls::vector<tls::asn1cert, 0, (1<<24)-1> certificate_list;
    std::vector<tls::asn1cert> certificate_list;
};

enum class hash_algorithm : uint8 {
    none = 0,
    md5  = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,
    sha512 = 6
};

std::ostream& operator<<(std::ostream& os, hash_algorithm h);

enum class signature_algorithm : uint8 {
      anonymous = 0,
      rsa       = 1,
      dsa       = 2,
      ecdsa     = 3
};


std::ostream& operator<<(std::ostream& os, signature_algorithm s);

struct signed_signature {
    tls::hash_algorithm              hash_algorithm;
    tls::signature_algorithm         signature_algorithm;
    tls::vector<uint8, 1, (1<<16)-1> value;

};

struct signature_and_hash_algorithm {
    hash_algorithm       hash;
    signature_algorithm  signature;
};

// Ephemeral DH parameters
struct server_dh_params {
    tls::vector<uint8, 1, (1<<16)-1> dh_p;  // The prime modulus used for the Diffie-Hellman operation.
    tls::vector<uint8, 1, (1<<16)-1> dh_g;  // The generator used for the Diffie-Hellman operation.
    tls::vector<uint8, 1, (1<<16)-1> dh_Ys; // The server's Diffie-Hellman public value (g^X mod p).
};

struct server_key_exchange_dhe {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::server_key_exchange;

    server_dh_params params;
    signed_signature signature;
};

struct server_hello_done {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::server_hello_done;
};

struct client_key_exchange_rsa {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::client_key_exchange;

    //Implementation note: Public-key-encrypted data is represented as an
    //opaque vector <0..2^16-1> (see Section 4.7).  Thus, the RSA-encrypted
    //PreMasterSecret in a ClientKeyExchange is preceded by two length
    //bytes.

    // For RSA
    vector<uint8, 0, (1<<16)-1> encrypted_pre_master_secret; // Always 48 bytes for RSA
};

struct client_key_exchange_dhe_rsa {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::client_key_exchange;
    vector<uint8, 1, (1<<16)-1> dh_Yc;
};

struct finished {
    static constexpr tls::handshake_type handshake_type = tls::handshake_type::finished;

    static constexpr size_t verify_data_min_length = 12;   // For RSA at least
    std::vector<uint8_t> verify_data;
};

struct handshake {
    static constexpr tls::content_type content_type = tls::content_type::handshake;

    tls::handshake_type type;

    using body_length_type = uint24;
    std::vector<uint8_t> body;
};

struct change_cipher_spec {
    static constexpr tls::content_type content_type = tls::content_type::change_cipher_spec;
    enum : uint8 { change_cipher_spec_type = 1 };
    /*enum change_cipher_spec_type type;*/
};

struct record {
    static constexpr size_t max_plaintext_length  = (1<<14)+2048;
    static constexpr size_t max_compressed_length = max_plaintext_length + 1024;
    static constexpr size_t max_ciphertext_length = max_compressed_length + 1024;

    content_type                            type;
    protocol_version                        version;

    using fragment_length_type = uint16;
    std::vector<uint8_t>                    fragment;
};


inline void append_to_buffer(std::vector<uint8_t>& buffer, uint8 item) {
    buffer.push_back(item);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, uint16 item) {
    buffer.push_back(item>>8);
    buffer.push_back(item);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, uint32 item) {
    buffer.push_back(item>>24);
    buffer.push_back(item>>16);
    buffer.push_back(item>>8);
    buffer.push_back(item);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, uint64 item) {
    buffer.push_back(item>>56);
    buffer.push_back(item>>48);
    buffer.push_back(item>>40);
    buffer.push_back(item>>32);
    buffer.push_back(item>>24);
    buffer.push_back(item>>16);
    buffer.push_back(item>>8);
    buffer.push_back(item);
}

template<typename EnumType, typename=typename std::enable_if<std::is_enum<EnumType>::value>::type>
void append_to_buffer(std::vector<uint8_t>& buffer, EnumType item)
{
    append_to_buffer(buffer, static_cast<typename std::underlying_type<EnumType>::type>(item));
}

template<unsigned BitCount, typename Underlying>
inline void append_to_buffer(std::vector<uint8_t>& buffer, const uint<BitCount, Underlying>& item) {
    const auto x = static_cast<Underlying>(item);
    for (unsigned i = 0; i < BitCount/8; ++i) {
        buffer.push_back(x >> ((BitCount/8-1-i)*8));
    }
}

template<unsigned ByteCount>
inline void append_to_buffer(std::vector<uint8_t>& buffer, const uint8 (&item)[ByteCount]) {
    buffer.insert(buffer.end(), item, item+ByteCount);
}

template<typename T, size_t LowerBoundInBytes, size_t UpperBoundInBytes>
inline void append_to_buffer(std::vector<uint8_t>& buffer, const vector<T, LowerBoundInBytes, UpperBoundInBytes>& item) {
    append_to_buffer(buffer, item.byte_count());
    for (size_t i = 0, sz = item.size(); i < sz; ++i) {
        append_to_buffer(buffer, item[i]);
    }
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& item) {
    buffer.insert(buffer.end(), item.begin(), item.end());
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const protocol_version& item) {
    buffer.push_back(item.major);
    buffer.push_back(item.minor);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const random& item) {
    append_to_buffer(buffer, item.gmt_unix_time);
    append_to_buffer(buffer, item.random_bytes);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const extension& item) {
    append_to_buffer(buffer, item.type);
    append_to_buffer(buffer, item.data);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const client_hello& item) {
    append_to_buffer(buffer, item.client_version);
    append_to_buffer(buffer, item.random);
    append_to_buffer(buffer, item.session_id);
    append_to_buffer(buffer, item.cipher_suites);
    append_to_buffer(buffer, item.compression_methods);

    if (!item.extensions.empty()) {
        std::vector<uint8_t> extension_buf;
        for (const auto& ext : item.extensions) {
            append_to_buffer(extension_buf, ext);
        }
        assert(extension_buf.size() < 65535);
        append_to_buffer(buffer, uint16(extension_buf.size()));
        append_to_buffer(buffer, extension_buf);
    }
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

inline void append_to_buffer(std::vector<uint8_t>& buffer, const client_key_exchange_rsa& item) {
    append_to_buffer(buffer, item.encrypted_pre_master_secret);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const client_key_exchange_dhe_rsa& item) {
    append_to_buffer(buffer, item.dh_Yc);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const finished& item) {
    append_to_buffer(buffer, item.verify_data);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const change_cipher_spec&) {
    buffer.push_back(change_cipher_spec::change_cipher_spec_type);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const server_dh_params& params) {
    append_to_buffer(buffer, params.dh_p);
    append_to_buffer(buffer, params.dh_g);
    append_to_buffer(buffer, params.dh_Ys);
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const handshake& item) {
    append_to_buffer(buffer, item.type);
    append_to_buffer(buffer, handshake::body_length_type(item.body.size()));
    append_to_buffer(buffer, item.body);
}

template<typename BodyType>
handshake make_handshake(const BodyType& body) {
    std::vector<uint8_t> body_buffer;
    append_to_buffer(body_buffer, body);
    return handshake{BodyType::handshake_type, body_buffer};
}

template<unsigned BitCount, typename Underlying>
inline void from_bytes(uint<BitCount, Underlying>& item, util::buffer_view& buffer) {
    item = util::get_be_uint<Underlying, BitCount>(buffer);
}
inline void from_bytes(uint8_t& item, util::buffer_view& buffer) {
    item = get_be_uint8(buffer);
}
inline void from_bytes(uint16_t& item, util::buffer_view& buffer) {
    item = get_be_uint16(buffer);
}
inline void from_bytes(uint32_t& item, util::buffer_view& buffer) {
    item = get_be_uint32(buffer);
}
inline void from_bytes(uint64_t& item, util::buffer_view& buffer) {
    item = get_be_uint64(buffer);
}

template<typename EnumType, typename=typename std::enable_if<std::is_enum<EnumType>::value>::type>
void from_bytes(EnumType& item, util::buffer_view& buffer)
{
    typename std::underlying_type<EnumType>::type x;
    from_bytes(x, buffer);
    item = static_cast<EnumType>(x);
}

template<unsigned ByteCount>
inline void from_bytes(uint8 (&item)[ByteCount], util::buffer_view& buffer) {
    buffer.read(item, ByteCount);
}

template<typename T, size_t LowerBoundInBytes, size_t UpperBoundInBytes>
inline void from_bytes(vector<T, LowerBoundInBytes, UpperBoundInBytes>& item, util::buffer_view& buffer) {
    typename smallest_possible_uint<8*log256(UpperBoundInBytes)>::type byte_count;
    from_bytes(byte_count, buffer);
    if (byte_count < LowerBoundInBytes) throw std::runtime_error("Byte count " + std::to_string(byte_count) + " < " + std::to_string(LowerBoundInBytes));
    if (byte_count > UpperBoundInBytes) throw std::runtime_error("Byte count " + std::to_string(byte_count) + " > " + std::to_string(UpperBoundInBytes));
    if (byte_count % sizeof(T)) throw std::runtime_error("Byte count " + std::to_string(byte_count) + " % " + std::to_string(sizeof(T)));
    std::vector<T> data(byte_count / sizeof(T));
    for (auto& subitem : data) {
        from_bytes(subitem, buffer);
    }
    item = vector<T, LowerBoundInBytes, UpperBoundInBytes>{data};
}

inline void from_bytes(alert& item, util::buffer_view& buffer) {
    from_bytes(item.level, buffer);
    from_bytes(item.description, buffer);
}

inline void from_bytes(protocol_version& item, util::buffer_view& buffer) {
    item.major = buffer.get();
    item.minor = buffer.get();
}

inline void from_bytes(random& item, util::buffer_view& buffer) {
    from_bytes(item.gmt_unix_time, buffer);
    from_bytes(item.random_bytes, buffer);
}

inline void from_bytes(signed_signature& item, util::buffer_view& buffer) {
    from_bytes(item.hash_algorithm, buffer);
    from_bytes(item.signature_algorithm, buffer);
    from_bytes(item.value, buffer);
}

inline void from_bytes(extension& item, util::buffer_view& buffer) {
    from_bytes(item.type, buffer);
    from_bytes(item.data, buffer);
}

inline void from_bytes(server_hello& item, util::buffer_view& buffer) {
    from_bytes(item.server_version, buffer);
    from_bytes(item.random, buffer);
    from_bytes(item.session_id, buffer);
    from_bytes(item.cipher_suite, buffer);
    from_bytes(item.compression_method, buffer);
    if (buffer.remaining()) {
        // Extensions
        assert(item.server_version == protocol_version_tls_1_2);

        uint16 bytes;
        from_bytes(bytes, buffer);
        // TODO: Better length validation
        if (bytes != buffer.remaining()) {
            throw std::runtime_error("Invalid ServerHello extensions list length got " + std::to_string(bytes) + " expected " + std::to_string(buffer.remaining()));
        }
        assert(item.extensions.empty());
        while (buffer.remaining()) {
            extension e;
            from_bytes(e, buffer);
            item.extensions.push_back(e);
        }
    }
}

inline void from_bytes(certificate& item, util::buffer_view& buffer) {
    // TODO: XXX: This is ugly...
    uint24 length;
    from_bytes(length, buffer);
    std::vector<tls::asn1cert> certificate_list;
    std::cout << "Reading " << length << " bytes of certificate data\n";
    size_t bytes_used = 0;
    for (;;) {
        uint24 cert_length;
        from_bytes(cert_length, buffer);
        std::cout << " Found certificate of length " << cert_length << "\n";
        if (!cert_length) throw std::runtime_error("Empty certificate found");
        std::vector<uint8> cert_data(cert_length);
        buffer.read(&cert_data[0], cert_data.size());
        certificate_list.emplace_back(std::move(cert_data));
        bytes_used+=cert_length+3;
        if (bytes_used >= length) {
            assert(bytes_used == length);
            break;
        }
    }
    item.certificate_list = std::move(certificate_list);
}

inline void from_bytes(server_dh_params& item, util::buffer_view& buffer) {
    from_bytes(item.dh_p, buffer);
    from_bytes(item.dh_g, buffer);
    from_bytes(item.dh_Ys, buffer);
}

inline void from_bytes(server_hello_done&, util::buffer_view& buffer) {
    assert(buffer.remaining() == 0);
}

inline void from_bytes(server_key_exchange_dhe& item, util::buffer_view& buffer) {
    from_bytes(item.params, buffer);
    from_bytes(item.signature, buffer);
}

inline void from_bytes(finished& item, util::buffer_view& buffer) {
    assert(buffer.remaining());
    item.verify_data.resize(buffer.remaining());
    buffer.read(&item.verify_data[0], item.verify_data.size());
}

inline void from_bytes(handshake& item, util::buffer_view& buffer) {
    handshake_type              type;
    handshake::body_length_type body_length;
    std::vector<uint8>          body;
    from_bytes(type, buffer);
    from_bytes(body_length, buffer);
    body.resize(body_length);
    if (body_length) {
        buffer.read(&body[0], body.size());
    }
    item = handshake{type, body};
}

template<typename HandshakeType>
inline HandshakeType get_as(const handshake& h) {
    if (h.type != HandshakeType::handshake_type) {
        throw std::runtime_error("Expected handshake of type " + std::to_string(int(HandshakeType::handshake_type)) + " got " + std::to_string(int(h.type)));
    }
    util::buffer_view body_buffer{h.body.data(), h.body.size()};
    HandshakeType inner;
    from_bytes(inner, body_buffer);
    if (body_buffer.remaining()) {
        throw std::runtime_error("Unread data in handshake of type " + std::to_string(int(HandshakeType::handshake_type)));
    }
    return inner;
}

template<typename T>
std::vector<uint8_t> as_buffer(const T& item) {
    std::vector<uint8_t> buffer;
    append_to_buffer(buffer, item);
    return buffer;
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const signature_and_hash_algorithm& item) {
    append_to_buffer(buffer, item.hash);
    append_to_buffer(buffer, item.signature);
}

using supported_signature_algorithms_list = vector<signature_and_hash_algorithm, 2, (1<<16)-2>;

inline extension make_supported_signature_algorithms(const supported_signature_algorithms_list& supported_signature_algorithms) {
    std::vector<uint8_t> buf;
    append_to_buffer(buf, supported_signature_algorithms);
    return extension{extension::signature_algorithms, buf};
}

// TODO: remove
std::vector<uint8_t> vec_concat(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

std::vector<uint8_t> PRF(prf_algorithm algo, const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& seed, size_t wanted_size);

std::vector<uint8_t> verification_buffer(uint64_t seq_no, content_type content_type, protocol_version version, uint16 length);

} } // namespace funtls::tls

#endif
