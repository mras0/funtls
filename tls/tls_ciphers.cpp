#include "tls_ciphers.h"
#include "tls.h"
#include <util/base_conversion.h>
#include <util/test.h>
#include <util/random.h>
#include <rc4/rc4.h>
#include <3des/3des.h>
#include <aes/aes.h>
#include <chacha/chacha.h>
#include <poly1305/poly1305.h>
#include <ostream>
#include <cassert>

using namespace funtls;

namespace {

class null_cipher : public tls::cipher {
public:
    explicit null_cipher(const tls::cipher_parameters& parameters) : cipher(parameters) {}
    virtual std::vector<uint8_t> do_process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) override {
        (void) verbuffer;
        return data;
    }
};

class mac_checked_cipher : public tls::cipher {
public:
    explicit mac_checked_cipher(const tls::cipher_parameters& parameters) : cipher(parameters) {}

private:
    std::vector<uint8_t> calc_mac(const std::vector<uint8_t>& content, std::vector<uint8_t> verbuffer);
    virtual std::vector<uint8_t> do_process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) override;
    virtual std::vector<uint8_t> do_process_content(const std::vector<uint8_t>& data) = 0;
};

std::vector<uint8_t> mac_checked_cipher::calc_mac(const std::vector<uint8_t>& content, std::vector<uint8_t> verbuffer) {
    assert(verbuffer.size() == 13);
    verbuffer[11] = static_cast<uint16_t>(content.size() >> 8);
    verbuffer[12] = static_cast<uint16_t>(content.size());
    // The MAC is generated as:
    // MAC(MAC_write_key, seq_num +
    //                  TLSCompressed.type +
    //                  TLSCompressed.version +
    //                  TLSCompressed.length +
    //                  TLSCompressed.fragment);
    auto hash_algo = parameters().hmac();
    hash_algo.input(verbuffer);
    hash_algo.input(content);
    return hash_algo.result();
}

std::vector<uint8_t> mac_checked_cipher::do_process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) {
    if (parameters().operation() == tls::cipher_parameters::encrypt) {
        auto mac = calc_mac(data, verbuffer);

        // 
        // Assemble content, mac and padding
        //
        // opaque content[TLSCompressed.length];
        // opaque MAC[SecurityParameters.mac_length];
        // uint8 padding[GenericBlockCipher.padding_length];
        // uint8 padding_length;
        //
        std::vector<uint8_t> content_and_mac;
        tls::append_to_buffer(content_and_mac, data);
        tls::append_to_buffer(content_and_mac, mac);
        //
        // padding:
        //    Padding that is added to force the length of the plaintext to be
        //    an integral multiple of the block cipher's block length.
        // padding_length:
        //    The padding length MUST be such that the total size of the
        //    GenericBlockCipher structure is a multiple of the cipher's block
        //    length.  Legal values range from zero to 255, inclusive.  This
        //    length specifies the length of the padding field exclusive of the
        //    padding_length field itself.
        const auto block_length = parameters().suite_parameters().block_length;
        if (block_length) {
            assert(parameters().suite_parameters().cipher_type == tls::cipher_type::block);
            uint8_t padding_length = block_length - (content_and_mac.size()+1) % block_length;
            for (unsigned i = 0; i < padding_length + 1U; ++i) {
                content_and_mac.push_back(padding_length);
            }
            assert(content_and_mac.size() % block_length == 0);
        } else {
            assert(parameters().suite_parameters().cipher_type == tls::cipher_type::stream);
        }

        auto fragment = do_process_content(content_and_mac);

        return fragment;
    } else {
        const auto decrypted = do_process_content(data);

        const auto cipher_param = parameters().suite_parameters();

        // check padding
        size_t padding_length = 0;
        size_t mac_index = 0;
        if (cipher_param.cipher_type == tls::cipher_type::block) {
            // TODO: FIX verification..
            padding_length = decrypted[decrypted.size()-1];
            //std::cout << "Decrypted.size() = " << decrypted.size() << std::endl;
            //std::cout << "mac_length = " << cipher_param.mac_length << std::endl;
            //std::cout << "Padding length = " << (int)padding_length << std::endl;
            mac_index = decrypted.size()-1-padding_length-cipher_param.mac_length;
            assert(decrypted.size() % cipher_param.block_length == 0);
            assert(padding_length + 1U < decrypted.size()); // Padding+Padding length byte musn't be sole contents
            for (unsigned i = 0; i < padding_length; ++i) assert(decrypted[decrypted.size()-1-padding_length] == padding_length);
        } else {
            assert(cipher_param.cipher_type == tls::cipher_type::stream);
            mac_index = decrypted.size()-cipher_param.mac_length;
        }

        // Extract MAC + Content
        const std::vector<uint8_t> mac{&decrypted[mac_index],&decrypted[mac_index+cipher_param.mac_length]};

        const std::vector<uint8_t> content{&decrypted[0],&decrypted[mac_index]};

        // Check MAC -- TODO: Unify with do_send
        const auto calced_mac = calc_mac(content, verbuffer);
        if (calced_mac != mac) {
            std::ostringstream msg;
            msg << "MAC check failed. Expected " << util::base16_encode(mac) << " got '" << util::base16_encode(calced_mac);
            FUNTLS_CHECK_FAILURE(msg.str());
        }

        return content;
    }
}

class rc4_cipher : public mac_checked_cipher {
public:
    explicit rc4_cipher(const tls::cipher_parameters& parameters);
private:
    virtual std::vector<uint8_t> do_process_content(const std::vector<uint8_t>& data) override;
    rc4::rc4 rc4_;
};

rc4_cipher::rc4_cipher(const tls::cipher_parameters& parameters) : mac_checked_cipher(parameters), rc4_(parameters.enc_key()) {
}

std::vector<uint8_t> rc4_cipher::do_process_content(const std::vector<uint8_t>& data) {
    auto buffer = data;
    rc4_.process(buffer);
    return buffer;
}

//
// A GenericBlockCipher consist of the initialization vector and block-ciphered
// content, mac and padding.
//

class generic_block_cipher : public mac_checked_cipher {
public:
    typedef std::vector<uint8_t> (*process_function)(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& data);
    explicit generic_block_cipher(const tls::cipher_parameters& parameters, process_function pf) : mac_checked_cipher(parameters), process_function_(pf) {}
private:
    process_function process_function_;
    virtual std::vector<uint8_t> do_process_content(const std::vector<uint8_t>& data) override {
        const auto iv_length = parameters().suite_parameters().record_iv_length;
        if (parameters().operation() == tls::cipher_parameters::decrypt) {
            FUNTLS_CHECK_BINARY(data.size(), >=, iv_length, "Message too small");
            // Extract initialization vector
            const std::vector<uint8_t> iv(&data[0],&data[iv_length]);
            const std::vector<uint8_t> encrypted(&data[iv_length],&data[data.size()]);
            return process_function_(parameters().enc_key(), iv, encrypted);
        } else {
            assert(parameters().operation() == tls::cipher_parameters::encrypt);
            // Generate initialization vector
            std::vector<uint8_t> message(iv_length);
            util::get_random_bytes(&message[0], message.size());
            tls::append_to_buffer(message, process_function_(parameters().enc_key(), message, data));
            return message;
        }
    }
};

class _3des_cipher : public generic_block_cipher {
public:
    explicit _3des_cipher(const tls::cipher_parameters& parameters)
        : generic_block_cipher(parameters, parameters.operation() == tls::cipher_parameters::encrypt ? &_3des::_3des_encrypt_cbc : &_3des::_3des_decrypt_cbc) {
    }
};

class aes_cbc_cipher : public generic_block_cipher {
public:
    explicit aes_cbc_cipher(const tls::cipher_parameters& parameters)
        : generic_block_cipher(parameters, parameters.operation() == tls::cipher_parameters::encrypt ? &aes::aes_encrypt_cbc : &aes::aes_decrypt_cbc) {
    }
};

class aes_gcm_cipher : public tls::cipher {
public:
    explicit aes_gcm_cipher(const tls::cipher_parameters& parameters) : cipher(parameters) {
    }
private:
    virtual std::vector<uint8_t> do_process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) override;
};

std::vector<uint8_t> aes_gcm_cipher::do_process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) {
    static constexpr unsigned tag_length = 16; // This is true for at least AES128. Probably all AES-GCM variants?

    const auto record_iv_length = parameters().suite_parameters().record_iv_length;
    if (parameters().operation() == tls::cipher_parameters::decrypt) {
        FUNTLS_CHECK_BINARY(data.size(), >=, record_iv_length + tag_length, "Message too small");
        // Extract initialization vector
        std::vector<uint8_t> iv = parameters().fixed_iv();
        tls::append_to_buffer(iv, std::vector<uint8_t>(&data[0],&data[record_iv_length]));
        assert(iv.size() == parameters().suite_parameters().fixed_iv_length + record_iv_length);
        const std::vector<uint8_t> encrypted(&data[record_iv_length],&data[data.size()-tag_length]);
        const std::vector<uint8_t> tag(&data[data.size()-tag_length],&data[data.size()]);

        auto vbuf = verbuffer;
        assert(vbuf.size()==13);
        vbuf[11] = static_cast<uint16_t>(encrypted.size()>>8);
        vbuf[12] = static_cast<uint16_t>(encrypted.size());

        //std::cout << "Calling aes_decrypt_gcm.\n";
        //std::cout << "Key  " << util::base16_encode(key_) << "\n";
        //std::cout << "IV   " << util::base16_encode(iv) << "\n";
        //std::cout << "C    " << util::base16_encode(encrypted) << "\n";
        //std::cout << "A    " << util::base16_encode(verbuffer) << std::endl;
        //std::cout << "T    " << util::base16_encode(tag) << std::endl;
        auto out = aes::aes_decrypt_gcm(parameters().enc_key(), iv, encrypted, vbuf, tag);
        //std::cout << "P->  " << util::base16_encode(out) << std::endl;
        return out;
    } else {
        assert(parameters().operation() == tls::cipher_parameters::encrypt);
        // Generate initialization vector
        std::vector<uint8_t> message(record_iv_length);
        util::get_random_bytes(&message[0], message.size());
        std::vector<uint8_t> iv = parameters().fixed_iv();
        tls::append_to_buffer(iv, message); // IV = salt || nonce_explicit
        //std::cout << "Calling aes_encrypt_gcm.\n";
        //std::cout << "Key  " << util::base16_encode(key_) << "\n";
        //std::cout << "IV   " << util::base16_encode(iv) << "\n";
        //std::cout << "data " << util::base16_encode(data) << "\n";
        //std::cout << "A    " << util::base16_encode(verbuffer) << std::endl;
        auto res = aes::aes_encrypt_gcm(parameters().enc_key(), iv, data, verbuffer);
        assert(res.second.size() == tag_length); // Auth tag (16 bytes for AES_128_GCM)
        tls::append_to_buffer(message, res.first); // C (cipher text)
        tls::append_to_buffer(message, res.second); // T (tag)
        //std::cout << "C    " << util::base16_encode(res.first) << std::endl;
        //std::cout << "T    " << util::base16_encode(res.second) << std::endl;

        //T = res.second;
        return message;
    }
}

class chacha20_cipher : public tls::cipher {
public:
    explicit chacha20_cipher(const tls::cipher_parameters& parameters) : cipher(parameters) {
    }
private:
    virtual std::vector<uint8_t> do_process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) override;
};

void append_le_u64(std::vector<uint8_t>& b, uint64_t x) {
    for (size_t i = 0; i < sizeof(x); ++i) {
        b.push_back(static_cast<uint8_t>(x));
        x >>= 8;
    }
}

std::vector<uint8_t> do_poly1305(const std::vector<uint8_t>& key, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& cipher_text)
{
    std::vector<uint8_t> buf = aad;
    append_le_u64(buf, aad.size());
    tls::append_to_buffer(buf, cipher_text);
    append_le_u64(buf, cipher_text.size());
    //std::cout << "poly1305 buffer: " << util::base16_encode(buf) << std::endl;
    return poly1305::poly1305(key, buf);
}

std::vector<uint8_t> chacha20_cipher::do_process(const std::vector<uint8_t>& data, const std::vector<uint8_t>& verbuffer) {
    static constexpr unsigned tag_length = 16;

    std::vector<uint8_t> nonce(4);//= parameters().fixed_iv();
    nonce.insert(nonce.end(), &verbuffer[0], &verbuffer[8]);
    assert(nonce.size() == chacha::nonce_length_bytes);
    const auto& key = parameters().enc_key();
    assert(key.size() == chacha::key_length_bytes);
    const auto one_time_key = chacha::poly1305_key_gen(key, nonce);
    //std::cout << "nonce " << util::base16_encode(nonce) << std::endl;
    //std::cout << "key   " << util::base16_encode(key) << std::endl;
    //std::cout << "otk   " << util::base16_encode(one_time_key) << std::endl;

    if (parameters().operation() == tls::cipher_parameters::decrypt) {
        FUNTLS_CHECK_BINARY(data.size(), >=, tag_length, "Not enough data");
        const std::vector<uint8_t> cipher_text(data.begin(), data.end() - tag_length);
        const std::vector<uint8_t> message_tag(data.end() - tag_length, data.end());
        auto vbuf = verbuffer;
        assert(vbuf.size()==13);
        vbuf[11] = static_cast<uint16_t>(cipher_text.size()>>8);
        vbuf[12] = static_cast<uint16_t>(cipher_text.size());
        //std::cout << "ctext " << util::base16_encode(cipher_text) << std::endl;
        //std::cout << "aad   " << util::base16_encode(vbuf) << std::endl;
        //std::cout << "mtag  " << util::base16_encode(message_tag) << std::endl;
        auto tag = do_poly1305(one_time_key, vbuf, cipher_text);
        //std::cout << "ctag  " << util::base16_encode(tag) << std::endl;
        if (tag != message_tag) {
            std::ostringstream msg;
            msg << "Tag check failed. Expected " << util::base16_encode(tag) << " got '" << util::base16_encode(message_tag);
            FUNTLS_CHECK_FAILURE(msg.str());
        }
        return chacha::chacha20(key, nonce, cipher_text);
    } else {
        assert(parameters().operation() == tls::cipher_parameters::encrypt);
        auto res = chacha::chacha20(key, nonce, data);
        //std::cout << "res   " << util::base16_encode(res) << std::endl;
        //std::cout << "aad   " << util::base16_encode(verbuffer) << std::endl;
        auto tag = do_poly1305(one_time_key, verbuffer, res);
        assert(tag.size() == tag_length);
        //std::cout << "tag   " << util::base16_encode(tag) << std::endl;
        tls::append_to_buffer(res, tag);
        return res;
    }
}

std::string cipher_suite_hex(tls::cipher_suite suite)
{
    const uint8_t b[2] = { static_cast<uint8_t>(static_cast<uint16_t>(suite) >> 8), static_cast<uint8_t>(static_cast<uint16_t>(suite)) };
    return util::base16_encode(b, sizeof(b));
}

template<tls::cipher_suite suite>
tls::cipher_suite_parameters from_suite_impl()
{
    using t = tls::cipher_suite_traits<suite>;
    return {
        t::cipher_suite,
        t::key_exchange_algorithm,
        t::prf_algorithm,
        t::bulk_cipher_algorithm,
        t::cipher_type,
        t::key_length,
        t::block_length,
        t::fixed_iv_length,
        t::record_iv_length,
        t::mac_algorithm,
        t::mac_length,
        t::mac_key_length
    };
}

bool try_consume(std::string& in, const std::string& t)
{
    if (in.substr(0, t.size()) == t) {
        in = in.substr(t.size());
        return true;
    }
    return false;
}

} // unnamed namespace

namespace funtls { namespace tls {

hash::hash_algorithm get_hash(hash_algorithm algo)
{
    switch (algo) {
    case hash_algorithm::none:   break;
    case hash_algorithm::md5:    return hash::md5{};
    case hash_algorithm::sha1:   return hash::sha1{};
    case hash_algorithm::sha224: return hash::sha224{};
    case hash_algorithm::sha256: return hash::sha256{};
    case hash_algorithm::sha384: return hash::sha384{};
    case hash_algorithm::sha512: return hash::sha512{};
    }
    assert(false);
    FUNTLS_CHECK_FAILURE("Unimplemented hash algorithm " + std::to_string((int)algo));
}

hash::hash_algorithm get_hmac(mac_algorithm algo, const std::vector<uint8_t>& key)
{
    switch (algo) {
    case mac_algorithm::null:        break;
    case mac_algorithm::hmac_md5:    return hash::hmac_md5{key};
    case mac_algorithm::hmac_sha1:   return hash::hmac_sha1{key};
    case mac_algorithm::hmac_sha256: return hash::hmac_sha256{key};
    case mac_algorithm::hmac_sha384: return hash::hmac_sha384{key};
    case mac_algorithm::hmac_sha512: return hash::hmac_sha512{key};
    }
    assert(false);
    FUNTLS_CHECK_FAILURE("Unimplemented MAC algorithm " + std::to_string((int)algo));
}

std::ostream& operator<<(std::ostream& os, key_exchange_algorithm e)
{
    switch (e) {
    case key_exchange_algorithm::null:          return os << "NULL";
    case key_exchange_algorithm::dhe_dss:       return os << "DHE_DSS";
    case key_exchange_algorithm::dhe_rsa:       return os << "DHE_RSA";
    case key_exchange_algorithm::dh_anon:       return os << "DH_anon";
    case key_exchange_algorithm::rsa:           return os << "RSA";
    case key_exchange_algorithm::dh_dss:        return os << "DH_DSS";
    case key_exchange_algorithm::dh_rsa:        return os << "DH_RSA";
    case key_exchange_algorithm::ecdh_ecdsa:    return os << "ECDH_ECDSA";
    case key_exchange_algorithm::ecdhe_ecdsa:   return os << "ECDHE_ECDSA";
    case key_exchange_algorithm::ecdh_rsa:      return os << "ECDH_RSA";
    case key_exchange_algorithm::ecdhe_rsa:     return os << "ECDHE_RSA";
    case key_exchange_algorithm::ecdh_anon:     return os << "ECDH_anon";
    }
    assert(false);
    return os << "Unknown TLS key exchange algorithm " << static_cast<unsigned>(e);
}

std::ostream& operator<<(std::ostream& os, prf_algorithm e)
{
    switch (e) {
    case prf_algorithm::sha256: return os << "TLS_PRF_SHA256";
    case prf_algorithm::sha384: return os << "TLS_PRF_SHA384";
    }
    assert(false);
    return os << "Unknown TLS PRF algorithm " << static_cast<unsigned>(e);
}

std::ostream& operator<<(std::ostream& os, bulk_cipher_algorithm e)
{
    switch (e) {
    case bulk_cipher_algorithm::null:     return os << "NULL";
    case bulk_cipher_algorithm::rc4:      return os << "RC4";
    case bulk_cipher_algorithm::_3des:    return os << "3DES";
    case bulk_cipher_algorithm::aes_cbc:  return os << "AES-CBC";
    case bulk_cipher_algorithm::aes_gcm:  return os << "AES-GCM";
    case bulk_cipher_algorithm::chacha20: return os << "CHACHA20";
    }
    assert(false);
    return os << "Unknown TLS bulk cipher algorithm " << static_cast<unsigned>(e);
}

std::ostream& operator<<(std::ostream& os, cipher_type e)
{
    switch (e) {
    case cipher_type::stream: return os << "stream";
    case cipher_type::block:  return os << "block";
    case cipher_type::aead:   return os << "AEAD";
    }
    assert(false);
    return os << "Unknown TLS cipher type " << static_cast<unsigned>(e);
}

std::ostream& operator<<(std::ostream& os, mac_algorithm e)
{
    switch (e) {
    case mac_algorithm::null:        return os << "NULL";
    case mac_algorithm::hmac_md5:    return os << "MD5";
    case mac_algorithm::hmac_sha1:   return os << "SHA";
    case mac_algorithm::hmac_sha256: return os << "SHA256";
    case mac_algorithm::hmac_sha384: return os << "SHA384";
    case mac_algorithm::hmac_sha512: return os << "SHA512";
    }
    assert(false);
    return os << "Unknown TLS MAC algorithm " << static_cast<unsigned>(e);
}

#define ALL_SUPPORTED_SUITES(f) \
        f(null_with_null_null);\
        f(rsa_with_rc4_128_md5);\
        f(rsa_with_rc4_128_sha);\
        f(rsa_with_3des_ede_cbc_sha);\
        f(rsa_with_aes_128_cbc_sha);\
        f(rsa_with_aes_256_cbc_sha);\
        f(rsa_with_aes_128_cbc_sha256);\
        f(rsa_with_aes_256_cbc_sha256);\
        f(dhe_rsa_with_3des_ede_cbc_sha);\
        f(dhe_rsa_with_aes_128_cbc_sha);\
        f(dhe_rsa_with_aes_256_cbc_sha);\
        f(dhe_rsa_with_aes_128_cbc_sha256);\
        f(dhe_rsa_with_aes_256_cbc_sha256);\
        f(rsa_with_aes_128_gcm_sha256);\
        f(rsa_with_aes_256_gcm_sha384);\
        f(ecdhe_ecdsa_with_aes_128_gcm_sha256);\
        f(ecdhe_ecdsa_with_aes_256_gcm_sha384);\
        f(ecdhe_rsa_with_aes_128_gcm_sha256);\
        f(ecdhe_rsa_with_aes_256_gcm_sha384);\
        f(ecdhe_rsa_with_chacha20_poly1305_sha256);

cipher_suite_parameters parameters_from_suite(cipher_suite suite)
{
    switch (suite) {
#define PARAMETERS_FROM_SUITE_CASE(cs) case cipher_suite::cs: return from_suite_impl<cipher_suite::cs>()
        ALL_SUPPORTED_SUITES(PARAMETERS_FROM_SUITE_CASE);
#undef PARAMETERS_FROM_SUITE_CASE
        default: // TODO: REMOVE
        break;
    }
    FUNTLS_CHECK_FAILURE("Unknown TLS cipher suite " + cipher_suite_hex(suite));
}

std::ostream& operator<<(std::ostream& os, cipher_suite suite)
{
    const auto csp = parameters_from_suite(suite);
    os << "TLS_" << csp.key_exchange_algorithm;
    os << "_WITH_";
    if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::rc4) {
        os << "RC4_" << 8*csp.key_length;
    } else if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::_3des) {
        os << "3DES_EDE_CBC";
    } else if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::aes_cbc) {
        os << "AES_" << 8*csp.key_length << "_CBC";
    } else if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::aes_gcm) {
        os << "AES_" << 8*csp.key_length << "_GCM";
    } else if (csp.bulk_cipher_algorithm == bulk_cipher_algorithm::chacha20) {
        os << "CHACHA20_POLY1305";
    } else {
        assert(csp.bulk_cipher_algorithm == bulk_cipher_algorithm::null);
    }
    os << "_" << csp.mac_algorithm;
    return os;
}

std::istream& operator>>(std::istream& is, cipher_suite& suite)
{
    std::string text;
    if (!(is >> text)) {
        return is;
    }
    const auto saved_text = text;
    // Convert to lowercase and replace - with _
    for (auto& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c += 'a'-'A';
        } else if (c == '-') {
            c = '_';
        }
    }
    // skip (optional) TLS_ prefix
    (void) try_consume(text, "tls_");

    // Parse key exchange algorithm
    key_exchange_algorithm kex_algo = key_exchange_algorithm::rsa;
    if (try_consume(text, "rsa_")) {
    } else if (try_consume(text, "dhe_rsa_")) {
        kex_algo = key_exchange_algorithm::dhe_rsa;
    } else if (try_consume(text, "ecdh_ecdsa_")) {
        kex_algo = key_exchange_algorithm::ecdh_ecdsa;
    } else if (try_consume(text, "ecdhe_ecdsa_")) {
        kex_algo = key_exchange_algorithm::ecdhe_ecdsa;
    } else if (try_consume(text, "ecdhe_rsa_")) {
        kex_algo = key_exchange_algorithm::ecdhe_rsa;
    }

    // Skip (optional) with_
    (void) try_consume(text, "with_");

    // Parse bulk cipher algorithm
    bulk_cipher_algorithm cipher_algo = bulk_cipher_algorithm::null;
    unsigned bits = 0;
    if (try_consume(text, "rc4_128_") || try_consume(text, "rc4_")) {
        cipher_algo = bulk_cipher_algorithm::rc4;
        bits = 128;
    } else if (try_consume(text, "3des_ede_cbc_") || try_consume(text, "des_cbc3_")) {
        cipher_algo = bulk_cipher_algorithm::_3des;
        bits = 192;
    } else if (try_consume(text, "aes_128_gcm_") || try_consume(text, "aes128_gcm_")) {
        cipher_algo = bulk_cipher_algorithm::aes_gcm;
        bits = 128;
    } else if (try_consume(text, "aes_128_cbc_") || try_consume(text, "aes128_")) {
        cipher_algo = bulk_cipher_algorithm::aes_cbc;
        bits = 128;
    } else if (try_consume(text, "aes_256_gcm_") || try_consume(text, "aes256_gcm_")) {
        cipher_algo = bulk_cipher_algorithm::aes_gcm;
        bits = 256;
    } else if (try_consume(text, "aes_256_cbc_") || try_consume(text, "aes256_")) {
        cipher_algo = bulk_cipher_algorithm::aes_cbc;
        bits = 256;
    } else if (try_consume(text, "chacha20_poly1305_")) {
        cipher_algo = bulk_cipher_algorithm::chacha20;
        bits = 256;
    } else {
        FUNTLS_CHECK_FAILURE("Could not parse block cipher algorithm from " + saved_text);
    }
    FUNTLS_CHECK_BINARY(cipher_algo, !=, bulk_cipher_algorithm::null, "Invalid bulk cipher algorithm specified");

    // Parse MAC algorithm
    mac_algorithm mac_algo = mac_algorithm::null;
    if (try_consume(text, "sha384")) {
        mac_algo = mac_algorithm::hmac_sha384;
    } else if (try_consume(text, "sha256")) {
        mac_algo = mac_algorithm::hmac_sha256;
    } else if (try_consume(text, "sha")) {
        mac_algo = mac_algorithm::hmac_sha1;
    } else if (try_consume(text, "md5")) {
        mac_algo = mac_algorithm::hmac_md5;
    } else {
        FUNTLS_CHECK_FAILURE("Could not parse MAC algorithm from " + saved_text);
    }
    FUNTLS_CHECK_BINARY(mac_algo, !=, mac_algorithm::null, "Invalid MAC algorithm");

    FUNTLS_CHECK_BINARY(text.size(), ==, 0, "Unparsed found in cipher suite '" + saved_text + "'");

#define MATCH_SUITE(cs) do {\
    using t = cipher_suite_traits<cipher_suite::cs>;\
    if (kex_algo != t::key_exchange_algorithm) break;\
    if (cipher_algo != t::bulk_cipher_algorithm) break;\
    if (bits/8 != t::key_length) break;\
    if (mac_algo != t::mac_algorithm) break;\
    suite = cipher_suite::cs;\
    return is;\
} while(0)
    ALL_SUPPORTED_SUITES(MATCH_SUITE);
#undef MATCH_SUITE
    std::ostringstream oss;
    oss << "KEX=" << kex_algo << " Cipher=" << cipher_algo << " bits=" << bits << " MAC=" << mac_algo;
    FUNTLS_CHECK_FAILURE("Not implemented for " + oss.str());
    suite = cipher_suite::null_with_null_null;
    return is;
}

std::ostream& operator<<(std::ostream& os, const cipher_suite_parameters& csp)
{
    os << "cipher_suite           = 0x" << cipher_suite_hex(csp.cipher_suite) << " " << csp.cipher_suite << '\n';
    os << "key_exchange_algorithm = " << csp.key_exchange_algorithm << '\n';
    os << "prf_algorithm          = " << csp.prf_algorithm << '\n';
    os << "bulk_cipher_algorithm  = " << csp.bulk_cipher_algorithm << '\n';
    os << "cipher_type            = " << csp.cipher_type << '\n';
    os << "key_length             = " << static_cast<unsigned>(csp.key_length) << '\n';
    os << "block_length           = " << static_cast<unsigned>(csp.block_length) << '\n';
    os << "fixed_iv_length        = " << static_cast<unsigned>(csp.fixed_iv_length) << '\n';
    os << "record_iv_length       = " << static_cast<unsigned>(csp.record_iv_length) << '\n';
    os << "mac_algorithm          = " << csp.mac_algorithm << '\n';
    os << "mac_length             = " << static_cast<unsigned>(csp.mac_length) << '\n';
    os << "mac_key_length         = " << static_cast<unsigned>(csp.mac_key_length) << ' ';
    return os;
}

cipher_parameters::cipher_parameters(enum operation op, const cipher_suite_parameters& suite_parameters, const std::vector<uint8_t>& mac_key, const std::vector<uint8_t>& enc_key, const std::vector<uint8_t>& fixed_iv)
    : operation_(op)
    , suite_parameters_(suite_parameters)
    , mac_key_(mac_key)
    , enc_key_(enc_key)
    , fixed_iv_(fixed_iv) {
    FUNTLS_CHECK_BINARY(mac_key_.size(),  ==, suite_parameters_.mac_key_length,  "Invalid MAC key length");
    FUNTLS_CHECK_BINARY(enc_key_.size(),  ==, suite_parameters_.key_length,      "Invalid encryption key length");
    FUNTLS_CHECK_BINARY(fixed_iv_.size(), ==, suite_parameters_.fixed_iv_length, "Invalid fixed IV length");
}

std::unique_ptr<cipher> make_cipher(const cipher_parameters& parameters)
{
    const auto bca = parameters.suite_parameters().bulk_cipher_algorithm;
    if (bca == tls::bulk_cipher_algorithm::null) {
        return std::unique_ptr<cipher>{new null_cipher(parameters)};
    } else if (bca == tls::bulk_cipher_algorithm::rc4) {
        return std::unique_ptr<cipher>{new rc4_cipher(parameters)};
    } else if (bca == tls::bulk_cipher_algorithm::_3des) {
        return std::unique_ptr<cipher>{new _3des_cipher(parameters)};
    } else if (bca == tls::bulk_cipher_algorithm::aes_cbc) {
        return std::unique_ptr<cipher>{new aes_cbc_cipher(parameters)};
    } else if (bca == tls::bulk_cipher_algorithm::aes_gcm) {
        return std::unique_ptr<cipher>{new aes_gcm_cipher(parameters)};
    } else if (bca == tls::bulk_cipher_algorithm::chacha20) {
        return std::unique_ptr<cipher>{new chacha20_cipher(parameters)};
    } else {
        std::ostringstream oss;
        oss << "Unsupported bulk_cipher_algorithm '" << bca << "'";
        FUNTLS_CHECK_FAILURE(oss.str());
    }
}

} } // namespace funtls::tls
