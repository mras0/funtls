#include <util/buffer.h>

namespace funtls { namespace tls {

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

inline void append_to_buffer(std::vector<uint8_t>& buffer, const server_hello& item) {
    append_to_buffer(buffer, item.server_version);
    append_to_buffer(buffer, item.random);
    append_to_buffer(buffer, item.session_id);
    append_to_buffer(buffer, item.cipher_suite);
    append_to_buffer(buffer, item.compression_method);

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
    uint32_t size = 0;
    for (const auto& c : item.certificate_list) {
        size += c.byte_count() + 3;
    }
    append_to_buffer(buffer, uint24(size));
    for (const auto& c : item.certificate_list) {
        append_to_buffer(buffer, c);
    }
}

inline void append_to_buffer(std::vector<uint8_t>& buffer, const server_hello_done& item) {
    (void) buffer; (void) item;
    // ServerHelloDone is empty
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

inline void from_bytes(client_hello& item, util::buffer_view& buffer) {
    from_bytes(item.client_version, buffer);
    from_bytes(item.random, buffer);
    from_bytes(item.session_id, buffer);
    from_bytes(item.cipher_suites, buffer);
    from_bytes(item.compression_methods, buffer);
    if (buffer.remaining()) {
        // Extensions
        assert(item.client_version == protocol_version_tls_1_2);

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
    //std::cout << "Reading " << length << " bytes of certificate data\n";
    size_t bytes_used = 0;
    for (;;) {
        uint24 cert_length;
        from_bytes(cert_length, buffer);
        //std::cout << " Found certificate of length " << cert_length << "\n";
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
    if (buffer.remaining() != 0) {
        throw std::runtime_error("Non empty server hello. Size: " + std::to_string(buffer.remaining()));
    }
}

inline void from_bytes(client_key_exchange_rsa& item, util::buffer_view& buffer) {
    from_bytes(item.encrypted_pre_master_secret, buffer);
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

inline std::vector<uint8_t> verification_buffer(uint64_t seq_no, content_type content_type, protocol_version version, uint16 length)
{
    std::vector<uint8_t> buffer;
    buffer.reserve(8 + 1 + 2 + 2);
    append_to_buffer(buffer, seq_no);
    append_to_buffer(buffer, content_type);
    append_to_buffer(buffer, version);
    append_to_buffer(buffer, length);
    return buffer;
}

} } // namespace funtls::tls
