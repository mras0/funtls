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
        using underlying_serialized_size_type = typename smallest_possible_uint<8*log256(UpperBoundInBytes)>::underlying_type;
        return static_cast<underlying_serialized_size_type>(data.size() * sizeof(T));
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

std::vector<uint8_t> PRF(prf_algorithm algo, const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& seed, size_t wanted_size);

} } // namespace funtls::tls

#endif
