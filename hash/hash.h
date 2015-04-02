#ifndef FUNTLS_HASH_HASH_H_INCLUDED
#define FUNTLS_HASH_HASH_H_INCLUDED

#include <vector>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <cassert>

namespace funtls { namespace hash {

enum class algorithm {
    sha1,
    sha224,
    sha256,
    sha384,
    sha512
};

//SHA1HashSize = 20, SHA224HashSize = 28, SHA256HashSize = 32,
//SHA384HashSize = 48, SHA512HashSize = 64,
//USHAMaxHashSize = SHA512HashSize,

namespace detail {
class algorithm_impl {
public:
    virtual void                 input(const void* data, size_t length) = 0;
    virtual std::vector<uint8_t> result() const = 0;
};

std::unique_ptr<algorithm_impl> make_impl(algorithm algo);
std::unique_ptr<algorithm_impl> make_hmac_impl(algorithm algo, const void* secret, size_t secret_length);

} // namespace detail

class hash_algorithm_base {
public:
    hash_algorithm_base& input(const void* data, size_t length) {
        impl_->input(data, length);
        return *this;
    }

    hash_algorithm_base& input(const std::vector<uint8_t>& v) {
        assert(!v.empty());
        return input(&v[0], v.size());
    }

    std::vector<uint8_t> result() const {
        return impl_->result();
    }

protected:
    hash_algorithm_base(std::unique_ptr<detail::algorithm_impl>&& impl)
        : impl_(std::move(impl)) {
    }

private:
    std::unique_ptr<detail::algorithm_impl> impl_;
};

template<algorithm algo>
class hash_algorithm : public hash_algorithm_base {
public:
    hash_algorithm()
        : hash_algorithm_base(detail::make_impl(algo)) {
    }
};

template<algorithm algo>
class hmac_algorithm : public hash_algorithm_base {
public:
    hmac_algorithm(const void* secret, size_t secret_length)
        : hash_algorithm_base(detail::make_hmac_impl(algo, secret, secret_length)) {
    }
    template<typename T>
    hmac_algorithm(const T& x)
        : hmac_algorithm(&x[0], x.size()) {
        static_assert(sizeof(x[0]) == 1, "");
        assert(!x.empty());
    }
};

using sha1        = hash_algorithm<algorithm::sha1>;
using sha224      = hash_algorithm<algorithm::sha224>;
using sha256      = hash_algorithm<algorithm::sha256>;
using sha384      = hash_algorithm<algorithm::sha384>;
using sha512      = hash_algorithm<algorithm::sha512>;

using hmac_sha1   = hmac_algorithm<algorithm::sha1>;
using hmac_sha224 = hmac_algorithm<algorithm::sha224>;
using hmac_sha256 = hmac_algorithm<algorithm::sha256>;
using hmac_sha384 = hmac_algorithm<algorithm::sha384>;
using hmac_sha512 = hmac_algorithm<algorithm::sha512>;

} } // namespace funtls::hash

#endif
