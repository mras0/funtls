#include "hash.h"
#include "sha.h"
#include <util/test.h>

namespace {

class sha_impl : public funtls::hash::detail::algorithm_impl {
public:
    sha_impl(SHAversion sha_type) {
        USHAReset(&context_, static_cast<SHAversion>(sha_type));
    }
    virtual void input(const void* data, size_t length) override {
        USHAInput(&context_, reinterpret_cast<const uint8_t*>(data), length);
    }
    virtual std::vector<uint8_t> result() override {
        std::vector<uint8_t> result(USHAHashSize(static_cast<SHAversion>(context_.whichSha)));
        USHAResult(&context_, &result[0]);
        return result;
    }
private:
    USHAContext context_;
};

class hmac_sha_impl : public funtls::hash::detail::algorithm_impl {
public:
    hmac_sha_impl(SHAversion sha_type, const void* secret, size_t secret_length) {
        hmacReset(&context_, static_cast<SHAversion>(sha_type), reinterpret_cast<const uint8_t*>(secret), secret_length);
    }
    virtual void input(const void* data, size_t length) override {
        hmacInput(&context_, reinterpret_cast<const uint8_t*>(data), length);
    }
    virtual std::vector<uint8_t> result() override {
        std::vector<uint8_t> result(USHAHashSize(static_cast<SHAversion>(context_.whichSha)));
        hmacResult(&context_, &result[0]);
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
        case algorithm::sha1:   return ptr_type{new sha_impl(SHA1)};
        case algorithm::sha224: return ptr_type{new sha_impl(SHA224)};
        case algorithm::sha256: return ptr_type{new sha_impl(SHA256)};
        case algorithm::sha384: return ptr_type{new sha_impl(SHA384)};
        case algorithm::sha512: return ptr_type{new sha_impl(SHA512)};
    }
    FUNTLS_CHECK_FAILURE("Unimplemented hashing algorithm " + std::to_string(int(algo)));
}

std::unique_ptr<algorithm_impl> make_hmac_impl(algorithm algo, const void* secret, size_t secret_length)
{
    using ptr_type = std::unique_ptr<algorithm_impl>;
    switch (algo) {
        case algorithm::sha1:   return ptr_type{new hmac_sha_impl(SHA1, secret, secret_length)};
        case algorithm::sha224: return ptr_type{new hmac_sha_impl(SHA224, secret, secret_length)};
        case algorithm::sha256: return ptr_type{new hmac_sha_impl(SHA256, secret, secret_length)};
        case algorithm::sha384: return ptr_type{new hmac_sha_impl(SHA384, secret, secret_length)};
        case algorithm::sha512: return ptr_type{new hmac_sha_impl(SHA512, secret, secret_length)};
    }
    FUNTLS_CHECK_FAILURE("Unimplemented HMAC algorithm " + std::to_string(int(algo)));
}

} // namespace detail
} } // namespace funtls::hash
