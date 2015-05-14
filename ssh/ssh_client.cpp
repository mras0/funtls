#include <iostream>
#include <ssh/ssh.h>
#include <util/test.h>
#include <util/base_conversion.h>
#include <util/int_util.h>
#include <x509/x509_rsa.h>
#include <hash/hash.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

namespace {

// From http://tools.ietf.org/html/rfc3526
int modp2048_g = 2;
int_type modp2048_p("0x"
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

#include <boost/asio.hpp>

// Unencrypted, no mac
void send_ssh_packet(boost::asio::ip::tcp::socket& socket, const std::vector<uint8_t>& payload)
{
    buffer_builder packet;
    const uint8_t padwidth = 8;
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
    boost::asio::write(socket, boost::asio::buffer(packet_buf));
}

std::vector<uint8_t> read_ssh_packet(boost::asio::ip::tcp::socket& socket)
{
    // TODO: Validation
    std::vector<uint8_t> rbuf(5);
    boost::asio::read(socket, boost::asio::buffer(rbuf));
    const auto r_size     = (((uint32_t)rbuf[0]<<24)|((uint32_t)rbuf[1]<<16)|((uint32_t)rbuf[2]<<8)|rbuf[3]);
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

void check_rsa_sig(util::buffer_view& buf) {
    const auto type = ssh::get_string(buf);
    FUNTLS_CHECK_BINARY(std::string(type.begin(), type.end()), ==, "ssh-rsa", "Invalid RSA key");
}

x509::rsa_public_key parse_rsa_key(const std::vector<uint8_t>& blob)
{
    util::buffer_view buf{blob.data(), blob.size()};
    check_rsa_sig(buf);
    auto e = asn1::integer::from_bytes_unsigned(ssh::get_string(buf));
    auto n = asn1::integer::from_bytes_unsigned(ssh::get_string(buf));
    FUNTLS_CHECK_BINARY(buf.remaining(), ==, 0, "Invalid RSA key");
    return {n, e};
}

std::vector<uint8_t> parse_rsa_sig(const std::vector<uint8_t>& blob)
{
    util::buffer_view buf{blob.data(), blob.size()};
    check_rsa_sig(buf);
    return ssh::get_string(buf);
}

template<typename IntType>
std::vector<uint8_t> mpint_to_string(const IntType& i, size_t size)
{
    auto bytes = be_uint_to_bytes(i, size);
    if (bytes[0] & 0x80) bytes.insert(bytes.begin(), 0);
    return bytes;
}

std::vector<uint8_t> generate_key(const std::vector<uint8_t>& K, const std::vector<uint8_t>& H, char letter, const std::vector<uint8_t>& session_id)
{
    const uint32_t x = K.size();
    const uint8_t klen[4] = { static_cast<uint8_t>(x>>24), static_cast<uint8_t>(x>>16), static_cast<uint8_t>(x>>8), static_cast<uint8_t>(x) };
    auto key = hash::sha1{}.input(klen).input(K).input(H).input(&letter, 1).input(session_id).result();
    std::cout << "key " << letter << std::endl;
    hexdump(std::cout, key);
    return key;
}

#define CHECK_CONTAINS(nl, n) FUNTLS_CHECK_BINARY(nl.contains(n), ==, true, nl2s(nl) + " doesn't contain " + n)

void test_client(const char* host, const char* port)
{
    boost::asio::io_service         io_service;
    boost::asio::ip::tcp::socket    socket(io_service);
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
        const int_type& p = modp2048_p;
        int_type x = rand_positive_int_less(p);
        int_type e = boost::multiprecision::powm(int_type(modp2048_g), x, p);
        std::cout << "e=" << e << std::endl;
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

        K = mpint_to_string(int_type(powm(ssh::string_to_int<int_type>(f), x, p)), ilog256(p));

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

    const std::vector<uint8_t> session_id = H; // the session id is the exchange hash from the first key exchange

    const auto client_iv      = generate_key(K, H, 'A', session_id);
    const auto server_iv      = generate_key(K, H, 'B', session_id);
    const auto client_key     = generate_key(K, H, 'C', session_id);
    const auto server_key     = generate_key(K, H, 'D', session_id);
    const auto client_mac_key = generate_key(K, H, 'E', session_id);
    const auto server_mac_key = generate_key(K, H, 'F', session_id);

    // TODO: Encrypt + Add MAC
    // Service request
    {
        buffer_builder b;
        put(b, ssh::message_type::service_request);
        put_string(b, "ssh-userauth");
        send_ssh_packet(socket, b.as_vector());
    }

}

int main()
{
    test_client("localhost", "1234");
}
