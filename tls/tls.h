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
#include <ostream>

#include <tls/tls_ciphers.h>

namespace funtls { namespace tls {

static constexpr size_t master_secret_size = 48;

template<unsigned BitCount, typename Underlying>
struct uint {
    static_assert(BitCount >= 8, "");
    static_assert(BitCount % 8 == 0, "");
    static_assert(sizeof(Underlying) * 8 > BitCount, "");

    static constexpr Underlying max_size = Underlying{1} << BitCount;

    using underlying_type = Underlying;

    uint(underlying_type value = 0) : value(value) {
        if (value >> BitCount) {
            throw std::logic_error(std::to_string(value) + " is out of range for uint<" + std::to_string(BitCount) + ">");
        }
    }

    operator underlying_type() const {
        assert(value < max_size);
        return value;
    }

private:
    underlying_type value;
};

using uint8  = uint8_t;
using uint16 = uint16_t;
using uint24 = uint<24, uint32_t>;
using uint32 = uint32_t;
using uint64 = uint64_t;

static_assert(std::is_trivially_copyable<uint24>::value, "");

template<unsigned BitCount>
struct smallest_possible_uint;

template<> struct smallest_possible_uint<8> { using type = uint8; using underlying_type = type; };
template<> struct smallest_possible_uint<16> { using type = uint16; using underlying_type = type; };
template<> struct smallest_possible_uint<24> { using type = uint24; using underlying_type = uint32_t; };
template<> struct smallest_possible_uint<32> { using type = uint32; using underlying_type = type; };
template<> struct smallest_possible_uint<64> { using type = uint64; using underlying_type = type; };

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
    static constexpr auto content_type = tls::content_type::alert;

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
std::ostream& operator<<(std::ostream& os, handshake_type h);

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

constexpr bool operator>=(const protocol_version& a, const protocol_version& b) {
    return a.major > b.major ? true : (a.major == b.major ? a.minor >= b.minor : false);
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
    static constexpr bool is_complex = !std::is_trivially_copyable<T>::value;

    static_assert(LowerBoundInBytes < UpperBoundInBytes, "Invalid vector bounds");
    static_assert(is_complex || LowerBoundInBytes % sizeof(T) == 0, "Invalid vector bounds");
    static_assert(is_complex || UpperBoundInBytes % sizeof(T) == 0, "Invalid vector bounds");

    constexpr vector() {
        //static_assert(LowerBoundInBytes == 0, "");
    }

    vector(const std::vector<T>& l) : data_(l) {
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
    vector(const T (&array)[size]) : data_(&array[0], &array[size]) {
        static_assert(sizeof(array) >= LowerBoundInBytes, "");
        static_assert(sizeof(array) <= UpperBoundInBytes, "");
    }

    template<typename Dummy = std::enable_if<!is_complex>>
    serialized_size_type byte_count(typename Dummy::type* = 0) const {
        using underlying_serialized_size_type = typename smallest_possible_uint<8*log256(UpperBoundInBytes)>::underlying_type;
        return static_cast<underlying_serialized_size_type>(data_.size() * sizeof(T));
    }

    bool empty() const {
        return data_.empty();
    }

    size_t size() const {
        return data_.size();
    }

    const T* data() const {
        return data_.data();
    }

    T operator[](size_t index) const {
        assert(index < size());
        return data_[index];
    }

    const std::vector<T>& as_vector() const {
        return data_;
    }

    auto begin() const {
        return data_.begin();
    }

    auto end() const {
        return data_.end();
    }

    void clear() {
        static_assert(LowerBoundInBytes == 0, "");
        data_.clear();
    }

    friend std::ostream& operator<<(std::ostream& os, const vector& v) {
        os << "{";
        for (const auto& e: v) {
            os << " " << e;
        }
        return os << " }";
    }

private:
    std::vector<T>  data_;
};

struct random {
    uint32   gmt_unix_time;
    uint8    random_bytes[28];
};
random make_random();

using session_id  = vector<uint8, 0, 32>;

enum class compression_method : uint8 {
    null = 0
};

// http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
enum class extension_type : uint16_t {
    server_name                             = 0,
    status_request                          = 5,
    elliptic_curves                         = 10,
    ec_point_formats                        = 11,
    signature_algorithms                    = 13,
    application_layer_protocol_negotiation  = 16,
    signed_certificate_timestamp            = 18,
    extended_master_secret                  = 23,
    session_ticket                          = 35,
    renegotiation_info                      = 65281,
};

std::ostream& operator<<(std::ostream& os, extension_type etype);

struct extension {
    using data_type = vector<uint8, 0, (1<<16)-1>;

    extension() : type(static_cast<extension_type>(-1)) {}
    
    extension(extension_type type, const data_type& data) : type(type), data(data) {}

    template<typename SpecificExtension>
    extension(const SpecificExtension& ext) : type(SpecificExtension::extension_type) {
        std::vector<uint8_t> buffer;
        append_to_buffer(buffer, ext);
        data = buffer;
    }

    extension_type  type;
    data_type       data;
};
static_assert(vector<extension, 0, (1<<16)-1>::is_complex, "");

struct client_hello {
    static constexpr auto handshake_type = tls::handshake_type::client_hello;

    protocol_version                          client_version;
    tls::random                               random;
    tls::session_id                           session_id;
    vector<cipher_suite, 2, (1<<16)-2>        cipher_suites;
    vector<compression_method, 1, (1<<8)-1>   compression_methods;
    vector<extension, 0, (1<<16)-1>           extensions;
};

struct server_hello {
    static constexpr auto handshake_type = tls::handshake_type::server_hello;

    protocol_version                server_version;
    tls::random                     random;
    tls::session_id                 session_id;
    tls::cipher_suite               cipher_suite;
    tls::compression_method         compression_method;
    vector<extension, 0, (1<<16)-1> extensions;
};

using asn1cert = vector<uint8, 1, (1<<24)-1>;

struct certificate {
    static constexpr auto handshake_type = tls::handshake_type::certificate;

    vector<asn1cert, 0, (1<<24)-1> certificate_list;
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
    tls::hash_algorithm         hash_algorithm;
    tls::signature_algorithm    signature_algorithm;
    vector<uint8, 1, (1<<16)-1> value;
};

struct signature_and_hash_algorithm {
    hash_algorithm       hash;
    signature_algorithm  signature;
};
std::ostream& operator<<(std::ostream& os, const signature_and_hash_algorithm& sh);

struct server_name {
    enum class server_name_type : uint8_t { host_name = 0 };

    server_name_type name_type;
    vector<uint8, 1, (1<<16)-1> name;
};

std::ostream& operator<<(std::ostream& os, server_name::server_name_type name_type);
std::ostream& operator<<(std::ostream& os, const server_name& name);

struct server_name_extension {
    static constexpr auto extension_type = tls::extension_type::server_name;
    vector<server_name, 1, (1<<16)-1> server_name_list;
};
std::ostream& operator<<(std::ostream& os, const server_name_extension& ext);

struct signature_algorithms_extension {
    static constexpr auto extension_type = tls::extension_type::signature_algorithms;

    vector<signature_and_hash_algorithm, 2, (1<<16)-2> supported_signature_algorithms_list;
};
std::ostream& operator<<(std::ostream& os, const signature_algorithms_extension& ext);

struct application_layer_protocol_negotiation_extension {
    static constexpr auto extension_type = tls::extension_type::application_layer_protocol_negotiation;

    struct protocol_name {
        vector<uint8, 1, (1<<8)-1> name;
    };

    vector<protocol_name, 2, (1<<16)-1> protocol_name_list;
};
std::ostream& operator<<(std::ostream& os, const application_layer_protocol_negotiation_extension::protocol_name& name);
std::ostream& operator<<(std::ostream& os, const application_layer_protocol_negotiation_extension& ext);

// Ephemeral DH parameters
struct server_dh_params {
    vector<uint8, 1, (1<<16)-1> dh_p;  // The prime modulus used for the Diffie-Hellman operation.
    vector<uint8, 1, (1<<16)-1> dh_g;  // The generator used for the Diffie-Hellman operation.
    vector<uint8, 1, (1<<16)-1> dh_Ys; // The server's Diffie-Hellman public value (g^X mod p).
};

struct server_key_exchange_dhe {
    static constexpr auto handshake_type = tls::handshake_type::server_key_exchange;

    server_dh_params params;
    signed_signature signature;
};

struct server_hello_done {
    static constexpr auto handshake_type = tls::handshake_type::server_hello_done;
};

struct client_key_exchange_rsa {
    static constexpr auto handshake_type = tls::handshake_type::client_key_exchange;

    //Implementation note: Public-key-encrypted data is represented as an
    //opaque vector <0..2^16-1> (see Section 4.7).  Thus, the RSA-encrypted
    //PreMasterSecret in a ClientKeyExchange is preceded by two length
    //bytes.

    // For RSA
    vector<uint8, 0, (1<<16)-1> encrypted_pre_master_secret; // Always 48 bytes for RSA
};

struct client_key_exchange_dhe_rsa {
    static constexpr auto handshake_type = tls::handshake_type::client_key_exchange;

    vector<uint8, 1, (1<<16)-1> dh_Yc;
};

struct finished {
    static constexpr auto handshake_type = tls::handshake_type::finished;

    static constexpr size_t verify_data_min_length = 12;   // For RSA at least
    std::vector<uint8_t> verify_data;
};

struct handshake {
    static constexpr auto content_type = tls::content_type::handshake;

    handshake_type type;
    vector<uint8, 0, (1<<24)-1> body;
};

struct change_cipher_spec {
    static constexpr auto content_type = tls::content_type::change_cipher_spec;
    enum : uint8 { change_cipher_spec_type = 1 };
};

struct record {
    static constexpr size_t max_plaintext_length  = (1<<14)+2048;
    static constexpr size_t max_compressed_length = max_plaintext_length + 1024;
    static constexpr size_t max_ciphertext_length = max_compressed_length + 1024;

    content_type                 type;
    protocol_version             version;
    vector<uint8, 1, (1<<16)-1>  fragment;
};

std::vector<uint8_t> PRF(prf_algorithm algo, const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& seed, size_t wanted_size);

} } // namespace funtls

#endif
