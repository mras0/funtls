#include <iostream>
#include <iomanip>
#include <ssh/ssh.h>
#include <util/test.h>
#include <util/base_conversion.h>
#include <int_util/int_util.h>
#include <x509/x509_rsa.h>
#include <x509/x509_io.h>
#include <hash/hash.h>
#include <aes/aes.h>

#include <int_util/int.h>
using namespace funtls;

namespace {

// From http://tools.ietf.org/html/rfc3526
int modp2048_g = 2;
large_uint modp2048_p("0x"
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
"15728E5A8AACAA68FFFFFFFFFFFFFFFF");

std::string nl2s(const ssh::name_list& nl) {
    std::ostringstream os;
    os << nl;
    return os.str();
}

void hexdump(std::ostream& os, const void* src, size_t len)
{
    auto s = reinterpret_cast<const uint8_t*>(src);
    for (size_t i = 0; i < len; i += 16) {
        size_t here = len - i;
        if (here > 16) here = 16;
        os << std::setw(4) << std::setfill('0') << i << ":" << std::hex;
        for (size_t j = i; j < i + here; ++j) {
            os << ' ' << std::setw(2) << unsigned(s[j]);
        }
        if (here < 16) for (size_t j = here; j < 16; ++j) os << "   ";
        os << "  ";
        for (size_t j = i; j < i + here; ++j) {
            const char c = s[j];
            os << (c >= 32 && c < 127 ? c : '.');
        }
        os << std::dec << std::setfill(' ');
        os << std::endl;
    }
}
void hexdump(std::ostream& os, const std::vector<uint8_t>& v)
{
    hexdump(os, v.data(), v.size());
}

} // unnamed namespace


class buffer_builder {
public:

    void put_u8(uint8_t x) { b_.push_back(x); }
    void put_u32(uint32_t x) {
        b_.push_back(static_cast<uint8_t>(x>>24));
        b_.push_back(static_cast<uint8_t>(x>>16));
        b_.push_back(static_cast<uint8_t>(x>>8));
        b_.push_back(static_cast<uint8_t>(x));
    }
    void put(const void* s, size_t len) {
        auto beg = reinterpret_cast<const uint8_t*>(s);
        b_.insert(b_.end(), beg, beg + len);
    }

    const std::vector<uint8_t>& as_vector() const { return b_; }
private:
    std::vector<uint8_t> b_;
};

void put(buffer_builder& b, ssh::message_type x) {
    b.put_u8(static_cast<uint8_t>(x));
}

template<size_t size>
void put(buffer_builder& b, uint8_t (&arr)[size]) {
    b.put(arr, size);
}
void put(buffer_builder& b, const std::vector<uint8_t>& v) {
    b.put(v.data(), v.size());
}

void put_string(buffer_builder& b, const std::vector<uint8_t>& v) {
    assert(v.size() < (1ULL<<32));
    b.put_u32(v.size());
    put(b, v);
}

void put_string(buffer_builder& b, const std::string& s) {
    put_string(b, std::vector<uint8_t>(s.data(), s.data() + s.size()));
}

void put(buffer_builder& b, const ssh::name_list& nl) {
    put_string(b, nl2s(nl));
}

std::vector<uint8_t> make_ssh_packet(const std::vector<uint8_t>& payload, const uint8_t padwidth = 8)
{
    buffer_builder packet;
    uint8_t padding = padwidth - (payload.size() + 4 + 1) % padwidth;
    if (padding < 4) padding += padwidth;
    packet.put_u32(payload.size() + 1 + padding);
    packet.put_u8(padding);
    put(packet, payload);
    put(packet, std::vector<uint8_t>(padding));
    auto packet_buf = packet.as_vector();
    assert(packet_buf.size() >= 16);
    assert(packet_buf.size() % padwidth == 0);
    assert(packet_buf.size() == payload.size() + 1 + 4 + padding);
    return packet_buf;
}

uint32_t u32_from_bytes(const uint8_t* b)
{
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}

void check_rsa_sig(util::buffer_view& buf) {
    const auto type = ssh::get_string(buf);
    FUNTLS_CHECK_BINARY(std::string(type.begin(), type.end()), ==, "ssh-rsa", "Invalid RSA key");
}

x509::rsa_public_key parse_rsa_key(const std::vector<uint8_t>& blob)
{
    util::buffer_view buf{blob.data(), blob.size()};
    check_rsa_sig(buf);
    auto e = asn1::integer::from_bytes(ssh::get_string(buf));
    auto n = asn1::integer::from_bytes(ssh::get_string(buf));
    FUNTLS_CHECK_BINARY(buf.remaining(), ==, 0, "Invalid RSA key");
    return {n, e};
}

std::vector<uint8_t> make_rsa_key(const asn1::integer& exponent, const asn1::integer& modolus)
{
    buffer_builder b;
    put_string(b, "ssh-rsa");
    auto e = exponent.as_vector();
    auto n = modolus.as_vector();
    put_string(b, e);
    put_string(b, n);
    return b.as_vector();
}

std::vector<uint8_t> parse_rsa_sig(const std::vector<uint8_t>& blob)
{
    util::buffer_view buf{blob.data(), blob.size()};
    check_rsa_sig(buf);
    return ssh::get_string(buf);
}

std::vector<uint8_t> make_rsa_sig(const std::vector<uint8_t>& sig_blob)
{
    buffer_builder b;
    put_string(b, "ssh-rsa");
    put_string(b, sig_blob);
    return b.as_vector();
}

template<typename IntType>
std::vector<uint8_t> mpint_to_string(const IntType& i, size_t size)
{
    auto bytes = be_uint_to_bytes(i, size);
    if (bytes[0] & 0x80) bytes.insert(bytes.begin(), 0);
    return bytes;
}

std::vector<uint8_t> u32buf(const uint32_t x) {
    return { static_cast<uint8_t>(x>>24), static_cast<uint8_t>(x>>16), static_cast<uint8_t>(x>>8), static_cast<uint8_t>(x) };
}

std::vector<uint8_t> generate_key(const std::vector<uint8_t>& K, const std::vector<uint8_t>& H, char letter, const std::vector<uint8_t>& session_id, size_t needed)
{
    auto key = hash::sha1{}.input(u32buf(K.size())).input(K).input(H).input(&letter, 1).input(session_id).result();
    std::cout << "key " << letter << std::endl;
    hexdump(std::cout, key);
    // key expansion not implemented
    assert(needed <= key.size());
    key.erase(key.begin() + needed, key.end());
    return key;
}

// *-ctr modes are described in RFC4344
std::vector<uint8_t> aes_ctr(const std::vector<uint8_t>& K, std::vector<uint8_t>& X, const std::vector<uint8_t>& input)
{
    FUNTLS_CHECK_BINARY(X.size(), !=, 0, "Invalid counter size");
    FUNTLS_CHECK_BINARY(input.size() % aes::block_size_bytes, ==, 0, "Input must be a multiple of 128-bit. Size="+std::to_string(input.size()));

    std::vector<uint8_t> res = input;
    for (size_t i = 0; i < input.size(); i += aes::block_size_bytes) {
        const auto B = aes::aes_encrypt_ecb(K, X);
        aes::increment_be_number(X.data(), X.size());
        for (size_t j = 0; j < aes::block_size_bytes; ++j) {
            res[i+j] ^= B[j];
        }
    }
    return res;
}

#include <boost/asio.hpp>

void send_ssh_packet(boost::asio::ip::tcp::socket& socket, const std::vector<uint8_t>& payload)
{
    boost::asio::write(socket, boost::asio::buffer(make_ssh_packet(payload)));
}

std::vector<uint8_t> read_ssh_packet(boost::asio::ip::tcp::socket& socket)
{
    // TODO: Validation
    std::vector<uint8_t> rbuf(5);
    boost::asio::read(socket, boost::asio::buffer(rbuf));
    const auto r_size     = u32_from_bytes(&rbuf[0]);
    const auto r_pad_size = rbuf[4];
    FUNTLS_CHECK_BINARY(r_size, <, 40000, "Invalid header: " + util::base16_encode(rbuf));
    rbuf.resize(r_size - r_pad_size - 1);
    boost::asio::read(socket, boost::asio::buffer(rbuf));
    auto r_payload = rbuf;
    // Padding
    rbuf.resize(r_pad_size);
    boost::asio::read(socket, boost::asio::buffer(rbuf));
    return r_payload;
}

class ssh_client {
public:
    ssh_client(const char* host, const char* port, const char* user_name, const x509::rsa_private_key& key);

private:
    boost::asio::io_service      io_service;
    boost::asio::ip::tcp::socket socket;

    std::vector<uint8_t>         session_id;

    uint32_t                     client_sequence_number = 0;
    std::vector<uint8_t>         client_iv;
    std::vector<uint8_t>         client_mac_key;
    std::vector<uint8_t>         client_key;

    uint32_t                     server_sequence_number = 0;
    std::vector<uint8_t>         server_iv;
    std::vector<uint8_t>         server_mac_key;
    std::vector<uint8_t>         server_key;

    void send_encrypted(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> recv_encrypted();

    void request_service(const std::string& service);
    void do_user_auth(const std::string& service, const std::string& user_name, const x509::rsa_private_key& key);
};

#define CHECK_CONTAINS(nl, n) FUNTLS_CHECK_BINARY(nl.contains(n), ==, true, nl2s(nl) + " doesn't contain " + n)
ssh_client::ssh_client(const char* host, const char* port, const char* user_name, const x509::rsa_private_key& key)
    : socket(io_service)
{
    boost::asio::ip::tcp::resolver  resolver(io_service);
    std::cout << "Connecting to " << host << ":" << port << " ..." << std::flush;
    boost::asio::connect(socket, resolver.resolve({host, port}));
    std::cout << " OK" << std::endl;

    // TODO: Allow other ID lines and check for ^SSH-2.0
    boost::asio::streambuf response_buf;
    boost::asio::read_until(socket, response_buf, "\r\n");
    std::istream response(&response_buf);
    std::string server_id;
    std::getline(response, server_id);
    assert(server_id.back() == '\r');
    server_id.pop_back();
    std::cout << "Server version: " << server_id << std::endl;

    // Send identification string
    // SSH-protoversion-softwareversion SP comments CR LF 
    static const std::string client_id = "SSH-2.0-funtls_0";
    boost::asio::write(socket, boost::asio::buffer(client_id+"\r\n")); // Be careful not to send NUL byte

    const std::string kex_algorithm = "diffie-hellman-group14-sha1";
    const std::string host_key_algorithm = "ssh-rsa";
    const std::string cipher = "aes128-ctr";
    const std::string mac = "hmac-sha1";
    const std::string compression = "none";
    const std::string lang = "";
    uint8_t client_cookie[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t server_cookie[16];

/*
      byte         SSH_MSG_KEXINIT
      byte[16]     cookie (random bytes)
      name-list    kex_algorithms
      name-list    server_host_key_algorithms
      name-list    encryption_algorithms_client_to_server
      name-list    encryption_algorithms_server_to_client
      name-list    mac_algorithms_client_to_server
      name-list    mac_algorithms_server_to_client
      name-list    compression_algorithms_client_to_server
      name-list    compression_algorithms_server_to_client
      name-list    languages_client_to_server
      name-list    languages_server_to_client
      boolean      first_kex_packet_follows
      uint32       0 (reserved for future extension)
*/
    std::vector<uint8_t> s_payload;
    std::vector<uint8_t> c_payload;
    {
        s_payload = read_ssh_packet(socket);
        util::buffer_view kexinit{s_payload.data(), s_payload.size()};
        FUNTLS_CHECK_BINARY(ssh::message_type::kexinit, ==, static_cast<ssh::message_type>(kexinit.get()), "Unexpect message type");
        kexinit.read(&server_cookie[0], sizeof(server_cookie));

        const auto kex_algorithms                          = ssh::name_list::from_buffer(kexinit);
        const auto server_host_key_algorithms              = ssh::name_list::from_buffer(kexinit);
        const auto encryption_algorithms_client_to_server  = ssh::name_list::from_buffer(kexinit);
        const auto encryption_algorithms_server_to_client  = ssh::name_list::from_buffer(kexinit);
        const auto mac_algorithms_client_to_server         = ssh::name_list::from_buffer(kexinit);
        const auto mac_algorithms_server_to_client         = ssh::name_list::from_buffer(kexinit);
        const auto compression_algorithms_client_to_server = ssh::name_list::from_buffer(kexinit);
        const auto compression_algorithms_server_to_client = ssh::name_list::from_buffer(kexinit);
        const auto languages_client_to_server              = ssh::name_list::from_buffer(kexinit);
        const auto languages_server_to_client              = ssh::name_list::from_buffer(kexinit);
        const auto first_kex_packet_follows                = kexinit.get();
        FUNTLS_CHECK_BINARY(util::get_be_uint32(kexinit), ==, 0, "Invalid KEXINIT");
        FUNTLS_CHECK_BINARY(kexinit.remaining(), ==, 0, "Invalid KEXINIT");
        std::cout << "kex_algorithms                          " << nl2s(kex_algorithms                          ) << std::endl;
        std::cout << "server_host_key_algorithms              " << nl2s(server_host_key_algorithms              ) << std::endl;
        std::cout << "encryption_algorithms_client_to_server  " << nl2s(encryption_algorithms_client_to_server  ) << std::endl;
        std::cout << "encryption_algorithms_server_to_client  " << nl2s(encryption_algorithms_server_to_client  ) << std::endl;
        std::cout << "mac_algorithms_client_to_server         " << nl2s(mac_algorithms_client_to_server         ) << std::endl;
        std::cout << "mac_algorithms_server_to_client         " << nl2s(mac_algorithms_server_to_client         ) << std::endl;
        std::cout << "compression_algorithms_client_to_server " << nl2s(compression_algorithms_client_to_server ) << std::endl;
        std::cout << "compression_algorithms_server_to_client " << nl2s(compression_algorithms_server_to_client ) << std::endl;
        std::cout << "languages_client_to_server              " << nl2s(languages_client_to_server              ) << std::endl;
        std::cout << "languages_server_to_client              " << nl2s(languages_server_to_client              ) << std::endl;
        std::cout << "first_kex_packet_follows                " << (unsigned)first_kex_packet_follows << std::endl;
        CHECK_CONTAINS(kex_algorithms, kex_algorithm);
        CHECK_CONTAINS(server_host_key_algorithms, host_key_algorithm);
        CHECK_CONTAINS(encryption_algorithms_client_to_server, cipher);
        CHECK_CONTAINS(encryption_algorithms_server_to_client, cipher);
        CHECK_CONTAINS(mac_algorithms_client_to_server, mac);
        CHECK_CONTAINS(mac_algorithms_server_to_client, mac);
        CHECK_CONTAINS(compression_algorithms_client_to_server, compression);
        CHECK_CONTAINS(compression_algorithms_server_to_client, compression);
        FUNTLS_CHECK_BINARY(nl2s(languages_client_to_server), ==, "", "Unsupported");
        FUNTLS_CHECK_BINARY(nl2s(languages_server_to_client), ==, "", "Unsupported");
        FUNTLS_CHECK_BINARY(first_kex_packet_follows, ==, 0, "Unsupported");
    }

    {
        buffer_builder b;
        put(b, ssh::message_type::kexinit);
        put(b, client_cookie);
        put_string(b, kex_algorithm);
        put_string(b, host_key_algorithm);
        put_string(b, cipher);
        put_string(b, cipher);
        put_string(b, mac);
        put_string(b, mac);
        put_string(b, compression);
        put_string(b, compression);
        put_string(b, lang);
        put_string(b, lang);
        b.put_u8(0); // first_kex_packet_follows
        b.put_u32(0);
        c_payload = b.as_vector();
        send_ssh_packet(socket, c_payload);
    }

    std::vector<uint8_t> K; // shared secret
    std::vector<uint8_t> H; // exchange hash
    {
        // Do kexdh_init
        // http://tools.ietf.org/html/rfc4253#section-8
        //  1. C generates a random number x (1 < x < q) and computes e = g^x mod p.  C sends e to S.
        const large_uint& p = modp2048_p;
        std::cout << "x " << std::flush;
        large_uint x = rand_positive_int_less(p);
        std::cout << x << std::endl;
        std::cout << "e " << std::flush;
        large_uint e = powm(large_uint(modp2048_g), x, p);
        std::cout << e << std::endl;
        auto e_bytes = be_uint_to_bytes(e, ilog256(modp2048_p));
        if (e_bytes[0]&0x80) e_bytes.insert(e_bytes.begin(), 0);
        buffer_builder b;
        put(b, ssh::message_type::kexdh_init);
        put_string(b, e_bytes);
        send_ssh_packet(socket, b.as_vector());

        auto r_payload = read_ssh_packet(socket);
        util::buffer_view kexdh_reply{r_payload.data(), r_payload.size()};
        FUNTLS_CHECK_BINARY(ssh::message_type::kexdh_reply, ==, static_cast<ssh::message_type>(kexdh_reply.get()), "Unexpect message type");

        const auto K_S = ssh::get_string(kexdh_reply);
        const auto f = ssh::get_string(kexdh_reply);
        const auto sig_H = ssh::get_string(kexdh_reply);

        K = mpint_to_string(large_uint(powm(ssh::string_to_int<large_uint>(f), x, p)), ilog256(p));

        buffer_builder hashb;
        put_string(hashb, client_id);
        put_string(hashb, server_id);
        put_string(hashb, c_payload);
        put_string(hashb, s_payload);
        put_string(hashb, K_S);
        put_string(hashb, e_bytes);
        put_string(hashb, f);
        put_string(hashb, K);
        H = hash::sha1{}.input(hashb.as_vector()).result();

        const auto calced_hash = hash::sha1{}.input(H).result();
        auto di = x509::pkcs1_decode(parse_rsa_key(K_S), parse_rsa_sig(sig_H));
        FUNTLS_CHECK_BINARY(di.digest_algorithm, ==, x509::id_sha1, "Invalid hash algorithm");
        std::cout << "H received " << util::base16_encode(di.digest) << std::endl;
        std::cout << "H calced   " << util::base16_encode(calced_hash) << std::endl;
        if (calced_hash != di.digest) {
            std::ostringstream msg;
            msg << "Key exchange failed. Invalid signature " << util::base16_encode(di.digest) << " expected " << util::base16_encode(calced_hash);
            FUNTLS_CHECK_FAILURE(msg.str());
        }
    }

    // Exchange SSH_MSG_NEWKEYS messages
    {
        send_ssh_packet(socket, {static_cast<uint8_t>(ssh::message_type::newkeys)});
        auto payload = read_ssh_packet(socket);
        FUNTLS_CHECK_BINARY(payload.size(), ==, 1, "Unexpected packet size for SSH_MSG_NEWKEYS");
        FUNTLS_CHECK_BINARY(ssh::message_type::newkeys, ==, static_cast<ssh::message_type>(payload[0]), "Unexpect message type");
    }

    session_id = H; // the session id is the exchange hash from the first key exchange

    constexpr size_t hmac_sha1_key_len = 20;
    constexpr size_t aes_128_key_len   = 128/8;

    client_iv      = generate_key(K, H, 'A', session_id, aes::block_size_bytes);
    server_iv      = generate_key(K, H, 'B', session_id, aes::block_size_bytes);
    client_key     = generate_key(K, H, 'C', session_id, aes_128_key_len);
    server_key     = generate_key(K, H, 'D', session_id, aes_128_key_len);
    client_mac_key = generate_key(K, H, 'E', session_id, hmac_sha1_key_len);
    server_mac_key = generate_key(K, H, 'F', session_id, hmac_sha1_key_len);
    client_sequence_number = 3;
    server_sequence_number = 3;

    do_user_auth("ssh-connection", user_name, key);
}

void ssh_client::send_encrypted(const std::vector<uint8_t>& payload)
{
    const auto unecrypted_packet = make_ssh_packet(payload, aes::block_size_bytes);
    const auto mac = hash::hmac_sha1{client_mac_key}.input(u32buf(client_sequence_number)).input(unecrypted_packet).result();

    std::cout << "mac " << util::base16_encode(mac) << std::endl;

    buffer_builder packet;
    put(packet, aes_ctr(client_key, client_iv, unecrypted_packet));
    put(packet, mac);
    boost::asio::write(socket, boost::asio::buffer(packet.as_vector()));
    ++client_sequence_number;
}

std::vector<uint8_t> ssh_client::recv_encrypted()
{
    for (;;) {
        std::vector<uint8_t> buf(16);
        boost::asio::read(socket, boost::asio::buffer(buf));

        hash::hmac_sha1 mac{server_mac_key};
        mac.input(u32buf(server_sequence_number));

        const auto first_block = aes_ctr(server_key, server_iv, buf);
        mac.input(first_block);
        const auto packet_size = u32_from_bytes(&first_block[0]);
        const auto pad_size    = first_block[4];
        FUNTLS_CHECK_BINARY(packet_size, <, 40000, "Invalid header: " + util::base16_encode(first_block));
        std::cout << "Packet size " << packet_size << " padding " << (unsigned)pad_size << std::endl;

        std::vector<uint8_t> payload(first_block.begin()+5,first_block.end());
        if (packet_size > 12) {
            buf.resize(packet_size - 1 - 11); // we already read the padding length byte and up to 11 bytes of data
            boost::asio::read(socket, boost::asio::buffer(buf));
            buf = aes_ctr(server_key, server_iv, buf);
            mac.input(buf);
            payload.insert(payload.end(), buf.begin(), buf.end());
        }
        // discard padding
        FUNTLS_CHECK_BINARY(payload.size(), >=, pad_size, "Not enough data");
        payload.erase(payload.end() - pad_size, payload.end());
        std::cout << util::base16_encode(payload) << std::endl;

        buf.resize(result_size(hash::algorithm::sha1));
        boost::asio::read(socket, boost::asio::buffer(buf));
        const auto calced_mac = mac.result();
        if (buf != calced_mac) {
            FUNTLS_CHECK_FAILURE("MAC check failed for server packet " + std::to_string(server_sequence_number));
        }
        ++server_sequence_number;
        if (!payload.empty()) {
            util::buffer_view msg{payload.data(), payload.size()};
            const auto msg_type = static_cast<ssh::message_type>(msg.get());
            if (msg_type == ssh::message_type::ignore) {
                auto msg_to_ignore = ssh::get_string(msg);
                FUNTLS_CHECK_BINARY(msg.remaining(), ==, 0, "Unexpected data");
                std::cout << msg_type << " " << std::string(msg_to_ignore.begin(), msg_to_ignore.end()) << std::endl;
                continue;
            } else if (msg_type == ssh::message_type::disconnect) {
                const auto reason      = static_cast<ssh::disconnect_reason>(util::get_be_uint32(msg));
                const auto description = ssh::get_string(msg);
                const auto language    = ssh::get_string(msg);
                FUNTLS_CHECK_BINARY(msg.remaining(), ==, 0, "Unexpected data");
                FUNTLS_CHECK_BINARY(std::string(language.begin(), language.end()), ==, "", "Untested");
                std::ostringstream oss;
                oss << "Disconnected: " << reason << " " << std::string(description.begin(), description.end()) << std::endl;
                throw std::runtime_error(oss.str());
            }
        }
        return payload;
    }
}

void ssh_client::request_service(const std::string& wanted_service)
{
    buffer_builder b;
    put(b, ssh::message_type::service_request);
    put_string(b, wanted_service);
    send_encrypted(b.as_vector());

    // Read service request response
    const auto msg_buf = recv_encrypted();
    util::buffer_view msg{msg_buf.data(), msg_buf.size()};
    FUNTLS_CHECK_BINARY(ssh::message_type::service_accept, ==, static_cast<ssh::message_type>(msg.get()), "Unexpected message");
    auto service_name = ssh::get_string(msg);
    FUNTLS_CHECK_BINARY(msg.remaining(), ==, 0, "Unexpected data");
    FUNTLS_CHECK_BINARY(std::string(service_name.begin(), service_name.end()), ==, wanted_service, "");
}

void ssh_client::do_user_auth(const std::string& service, const std::string& user_name, const x509::rsa_private_key& key)
{
    request_service("ssh-userauth");

    bool include_sig = false;
    for (;;) {
        buffer_builder b;
        put(b, ssh::message_type::userauth_request);
        put_string(b, user_name);
        put_string(b, service);

        //put_string(b, "none");  // method

        //put_string(b, "password");
        //b.put_u8(0); // FALSE
        //put_string(b, "plaintextpassword");
        put_string(b, "publickey");
        b.put_u8(include_sig);
        put_string(b, "rsa");
        auto pk_blob = make_rsa_key(key.public_exponent, key.modulus);
        put_string(b, pk_blob);

        if (include_sig) {
            std::vector<uint8_t> verbuf = u32buf(session_id.size());
            verbuf.insert(verbuf.end(), session_id.begin(), session_id.end());
            verbuf.insert(verbuf.end(), b.as_vector().begin(), b.as_vector().end());
            hexdump(std::cout, verbuf);
            auto digest_info = hash::sha1{}.input(verbuf).result();
            std::cout << "Calced " << util::base16_encode(digest_info) << std::endl;
            digest_info.insert(digest_info.begin(), {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14});
            std::vector<uint8_t> sig_blob = x509::pkcs1_encode(key, digest_info);
            put_string(b, make_rsa_sig(sig_blob));
            // Check that we can decode the message we produced
            auto di = x509::pkcs1_decode(x509::rsa_public_key{key.modulus, key.public_exponent}, sig_blob);
            FUNTLS_CHECK_BINARY(di.digest_algorithm.id(), ==, x509::id_sha1, "");
        }

        send_encrypted(b.as_vector());
        const auto msg_buf = recv_encrypted();
        FUNTLS_CHECK_BINARY(msg_buf.empty(), ==, false, "Got empty reply to userauth request");
        const auto msg_type = static_cast<ssh::message_type>(msg_buf[0]);
        std::cout << "Got " << msg_type << std::endl;
        if (msg_type == ssh::message_type::userauth_failure) {
            util::buffer_view msg{msg_buf.data()+1, msg_buf.size()-1};
            auto methods = ssh::name_list::from_buffer(msg);
            auto partial_sucess = msg.get();
            FUNTLS_CHECK_BINARY(msg.remaining(), ==, 0, "Unexpected data");
            std::cout << "Methods that can continue: " << nl2s(methods) << std::endl;
            if (partial_sucess) std::cout << "Partial sucess\n";
            FUNTLS_CHECK_FAILURE("");
        } else if (msg_type == ssh::message_type::userauth_pk_ok) {
            util::buffer_view msg{msg_buf.data()+1, msg_buf.size()-1};
            auto algo = ssh::get_string(msg);
            auto blob = ssh::get_string(msg);
            FUNTLS_CHECK_BINARY(std::string(algo.begin(), algo.end()), ==, "rsa", "");
            FUNTLS_CHECK_BINARY(util::base16_encode(blob), ==, util::base16_encode(pk_blob), "");
            FUNTLS_CHECK_BINARY(msg.remaining(), ==, 0, "Unexpected data");
            include_sig = true;
            continue;
        } else if (msg_type == ssh::message_type::userauth_success) {
            FUNTLS_CHECK_BINARY(msg_buf.size(), ==, 1, "Unexpected data");
            break;
        } else {
            std::cout << util::base16_encode(msg_buf) << std::endl;
            FUNTLS_CHECK_FAILURE("");
        }
    }

    std::cout << "Sucessfully authed as " << user_name << std::endl;
}


int main()
{
    const char* u = getenv("USER");
    const char* user_name = u && u[0] ? u : "test";
    const auto private_key = x509::rsa_private_key_from_pki(x509::read_pem_private_key_from_file("../rsa-key.pem"));
    ssh_client client("localhost", "1234", user_name, private_key);
}
