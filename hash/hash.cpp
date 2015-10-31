#include "hash.h"
#include <sha/sha.h>
#include <md5/md5.h>
#include <util/test.h>

namespace {

class md5_impl : public funtls::hash::detail::algorithm_impl {
public:
    static constexpr size_t hash_size = 128 / 8;
    static constexpr size_t block_size = 64;

    md5_impl() {
        MD5Init(&context_);
    }
    virtual void input(const void* data, size_t length) override {
        MD5Update(&context_, reinterpret_cast<const uint8_t*>(data), static_cast<unsigned>(length));
    }
    virtual std::vector<uint8_t> result() const override {
        std::vector<uint8_t> result(hash_size);
        auto context = context_; // Make local copy to avoid modifying the local state
        MD5Final(&context, &result[0]);
        return result;
    }
private:
    MD5_CTX context_;
};

// HMAC implemented from wikipedia pseudo-code
class hmac_md5_impl : public funtls::hash::detail::algorithm_impl {
public:
    //
    // The HMAC is calculated as follows:
    //
    // o_key_pad = [0x5c * blocksize] ^ key // Where blocksize is that of the underlying hash function
    // i_key_pad = [0x36 * blocksize] ^ key // Where ^ is exclusive or (XOR)
    // return hash(o_key_pad || hash(i_key_pad || message)) // Where || is concatenation
    //

    using hash_type = md5_impl;

    hmac_md5_impl(const void* secret, size_t secret_length) : o_key_pad_() {
        std::vector<uint8_t> key(reinterpret_cast<const uint8_t*>(secret), reinterpret_cast<const uint8_t*>(secret)+secret_length);
        if (key.size() > hash_type::block_size) {
            auto h = hash_type{};
            h.input(&key[0], key.size());
            key = h.result(); // keys longer than blocksize are shortened
        }
        if (key.size() < hash_type::block_size) {
            key.resize(hash_type::block_size);         // keys shorter than blocksize are zero-padded
        }

        constexpr uint8_t i_pad = 0x36;
        constexpr uint8_t o_pad = 0x5c;

        // Start by initializing the inner hash with the inner padding
        uint8_t i_key_pad[hash_type::block_size];
        for (size_t i = 0; i < hash_type::block_size; ++i) {
            i_key_pad[i] = i_pad ^ key[i];
        }
        inner_hash_.input(i_key_pad, sizeof(i_key_pad));

        // And produce the outer padding
        for (size_t i = 0; i < hash_type::block_size; ++i) {
            o_key_pad_[i] = o_pad ^ key[i];
        }

        // Raw secret no longer needed
    }
    virtual void input(const void* data, size_t length) override {
        inner_hash_.input(data, length);
    }
    virtual std::vector<uint8_t> result() const override {
        // Produce final result by hashing the outer key padding concatenated
        // with the result of the inner hash (i_key_pad || message)
        auto o_hash = hash_type{};
        o_hash.input(o_key_pad_, hash_type::block_size);
        auto inner_hash_result = inner_hash_.result();
        o_hash.input(&inner_hash_result[0], inner_hash_result.size());
        return o_hash.result();
    }
private:
    uint8_t              o_key_pad_[hash_type::block_size];
    hash_type            inner_hash_;
};

class sha_impl : public funtls::hash::detail::algorithm_impl {
public:
    sha_impl(SHAversion sha_type) {
        USHAReset(&context_, static_cast<SHAversion>(sha_type));
    }
    virtual void input(const void* data, size_t length) override {
        USHAInput(&context_, reinterpret_cast<const uint8_t*>(data), static_cast<unsigned>(length));
    }
    virtual std::vector<uint8_t> result() const override {
        std::vector<uint8_t> result(USHAHashSize(static_cast<SHAversion>(context_.whichSha)));
        auto context = context_; // Make local copy to avoid modifying the local state
        USHAResult(&context, &result[0]);
        return result;
    }
private:
    USHAContext context_;
};

class hmac_sha_impl : public funtls::hash::detail::algorithm_impl {
public:
    hmac_sha_impl(SHAversion sha_type, const void* secret, size_t secret_length) {
        hmacReset(&context_, static_cast<SHAversion>(sha_type), reinterpret_cast<const uint8_t*>(secret), static_cast<int>(secret_length));
    }
    virtual void input(const void* data, size_t length) override {
        hmacInput(&context_, reinterpret_cast<const uint8_t*>(data), static_cast<int>(length));
    }
    virtual std::vector<uint8_t> result() const override {
        std::vector<uint8_t> result(USHAHashSize(static_cast<SHAversion>(context_.whichSha)));
        auto context = context_; // Make local copy to avoid modifying the local state
        hmacResult(&context, &result[0]);
        return result;
    }
private:
    HMACContext context_;
};

} // unnamed namespace

namespace funtls { namespace hash {
namespace detail {

std::unique_ptr<algorithm_impl> make_impl(algorithm algo)
{
    using ptr_type = std::unique_ptr<algorithm_impl>;
    switch (algo) {
        case algorithm::md5:    return ptr_type{new md5_impl{}};
        case algorithm::sha1:   return ptr_type{new sha_impl{SHA1}};
        case algorithm::sha224: return ptr_type{new sha_impl{SHA224}};
        case algorithm::sha256: return ptr_type{new sha_impl{SHA256}};
        case algorithm::sha384: return ptr_type{new sha_impl{SHA384}};
        case algorithm::sha512: return ptr_type{new sha_impl{SHA512}};
    }
    FUNTLS_CHECK_FAILURE("Unimplemented hashing algorithm " + std::to_string(int(algo)));
}

std::unique_ptr<algorithm_impl> make_hmac_impl(algorithm algo, const void* secret, size_t secret_length)
{
    using ptr_type = std::unique_ptr<algorithm_impl>;
    switch (algo) {
        case algorithm::md5:    return ptr_type{new hmac_md5_impl{secret, secret_length}};
        case algorithm::sha1:   return ptr_type{new hmac_sha_impl{SHA1,   secret, secret_length}};
        case algorithm::sha224: return ptr_type{new hmac_sha_impl{SHA224, secret, secret_length}};
        case algorithm::sha256: return ptr_type{new hmac_sha_impl{SHA256, secret, secret_length}};
        case algorithm::sha384: return ptr_type{new hmac_sha_impl{SHA384, secret, secret_length}};
        case algorithm::sha512: return ptr_type{new hmac_sha_impl{SHA512, secret, secret_length}};
    }
    FUNTLS_CHECK_FAILURE("Unimplemented HMAC algorithm " + std::to_string(int(algo)));
}

} // namespace detail
} } // namespace funtls::hash
