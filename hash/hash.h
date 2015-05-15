#ifndef FUNTLS_HASH_HASH_H_INCLUDED
#define FUNTLS_HASH_HASH_H_INCLUDED

#include <vector>
#include <cstdint>
#include <cstddef>
#include <memory>

namespace funtls { namespace hash {

enum class algorithm {
    md5,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512
};

constexpr size_t result_size(algorithm algo) {
    return algo == algorithm::md5    ? 16
         : algo == algorithm::sha1   ? 20
         : algo == algorithm::sha224 ? 28
         : algo == algorithm::sha256 ? 32
         : algo == algorithm::sha384 ? 48
         : /* algo == algorithm::sha512 ? */ 64;
}

namespace detail {
class algorithm_impl {
public:
    virtual void                 input(const void* data, size_t length) = 0;
    virtual std::vector<uint8_t> result() const = 0;
};

std::unique_ptr<algorithm_impl> make_impl(algorithm algo);
std::unique_ptr<algorithm_impl> make_hmac_impl(algorithm algo, const void* secret, size_t secret_length);

} // namespace detail

class hash_algorithm {
public:
    hash_algorithm& input(const void* data, size_t length) {
        impl_->input(data, length);
        return *this;
    }

    template<size_t size>
    hash_algorithm& input(const uint8_t (&arr)[size]) {
        return input(arr, size);
    }

    hash_algorithm& input(const std::vector<uint8_t>& v) {
        return input(v.size() ? &v[0] : nullptr, v.size());
    }

    std::vector<uint8_t> result() const {
        return impl_->result();
    }

protected:
    hash_algorithm(std::unique_ptr<detail::algorithm_impl>&& impl)
        : impl_(std::move(impl)) {
    }

private:
    std::unique_ptr<detail::algorithm_impl> impl_;
};

template<algorithm algo>
class hash_algorithm_impl : public hash_algorithm {
public:
    hash_algorithm_impl()
        : hash_algorithm(detail::make_impl(algo)) {
    }
};

template<algorithm algo>
class hmac_algorithm_impl : public hash_algorithm {
public:
    hmac_algorithm_impl(const void* secret, size_t secret_length)
        : hash_algorithm(detail::make_hmac_impl(algo, secret, secret_length)) {
    }
    template<typename T>
    hmac_algorithm_impl(const T& x)
        : hmac_algorithm_impl(x.size() ? &x[0] : nullptr, x.size()) {
        static_assert(sizeof(x[0]) == 1, "");
    }
};

using md5         = hash_algorithm_impl<algorithm::md5>;
using sha1        = hash_algorithm_impl<algorithm::sha1>;
using sha224      = hash_algorithm_impl<algorithm::sha224>;
using sha256      = hash_algorithm_impl<algorithm::sha256>;
using sha384      = hash_algorithm_impl<algorithm::sha384>;
using sha512      = hash_algorithm_impl<algorithm::sha512>;

using hmac_md5    = hmac_algorithm_impl<algorithm::md5>;
using hmac_sha1   = hmac_algorithm_impl<algorithm::sha1>;
using hmac_sha224 = hmac_algorithm_impl<algorithm::sha224>;
using hmac_sha256 = hmac_algorithm_impl<algorithm::sha256>;
using hmac_sha384 = hmac_algorithm_impl<algorithm::sha384>;
using hmac_sha512 = hmac_algorithm_impl<algorithm::sha512>;

} } // namespace funtls::hash

#endif
