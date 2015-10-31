#ifndef UTIL_ASYNC_RESULT_H_INCLUDED
#define UTIL_ASYNC_RESULT_H_INCLUDED

#include <utility>
#include <exception>
#include <new>
#include <functional>
#include <assert.h>

namespace funtls { namespace util {

template<typename T>
class async_result {
public:
    async_result(T&& result) : async_result() {
        construct(std::move(result));
    }

    async_result(std::exception_ptr exception) : async_result() {
        construct(exception);
    }

    async_result(async_result&& rhs) : async_result() {
        if (rhs.state_ == has_exception) {
            construct(rhs.exception_);
        } else {
            construct(std::move(rhs.result_));
        }
    }

    async_result(const async_result&) = delete;

    ~async_result() {
        destruct();
    }

    async_result& operator=(async_result&& rhs) {
        destruct();
        if (rhs.state_ == has_exception) {
            construct(rhs.excption_);
        } else {
            construct(std::move(rhs.result_));
        }
        return *this;
    }

    async_result& operator=(const async_result&) = delete;

    explicit operator bool() const {
        return state_ != has_exception;
    }

    T&& get() {
        if (state_ == has_exception) {
            std::rethrow_exception(exception_);
        }
        return std::move(result_);
    }

    std::exception_ptr get_exception() const {
        assert(state_ == has_exception);
        return exception_;
    }

private:
    async_result() : state_(has_exception), exception_(nullptr) {}

    enum { has_result, has_exception } state_;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4624) // warning C4624: 'X': destructor was implicitly defined as deleted because a base class destructor is inaccessible or deleted
#endif
    union {
        T                  result_;
        std::exception_ptr exception_;
    };
#ifdef _MSC_VER
#pragma warning(pop)
#endif

    void construct(T&& result) {
        state_ = has_result;
        new (&result_) T(std::move(result));
    }

    void construct(std::exception_ptr exception) {
        state_ = has_exception;
        new (&exception_) std::exception_ptr(exception);
    }

    void destruct() {
        if (state_ == has_exception) {
            exception_.~exception_ptr();
        } else {
            result_.~T();
        }
    }
};

template<>
class async_result<void> {
public:
    async_result() : exception_(nullptr) {
    }

    async_result(std::exception_ptr exception) : exception_(exception) {
    }

    async_result(async_result&& rhs) : exception_(rhs.exception_) {
    }

    async_result(const async_result&) = delete;

    async_result& operator=(async_result&& rhs) {
        exception_ = rhs.exception_;
        return *this;
    }

    async_result& operator=(const async_result&) = delete;

    explicit operator bool() const {
        return !exception_;
    }

    void get() {
        if (exception_) {
            std::rethrow_exception(exception_);
        }
    }

    std::exception_ptr get_exception() const {
        assert(exception_);
        return exception_;
    }

private:
    std::exception_ptr exception_;
};

template<typename T>
inline async_result<T> make_async_result(T&& result) {
    return async_result<T>(std::move(result));
}

inline async_result<void> make_async_result() {
    return async_result<void>{};
}

namespace detail {
template<typename T>
struct arg_type;

template<typename T>
struct arg_type : public arg_type<decltype(&T::operator())> {
};

template<typename C, typename R>
struct arg_type<R (C::*)() const> {
    using type = void;
};

template<typename C, typename R, typename A>
struct arg_type<R (C::*)(A&&) const> {
    using type = A;
};
} // namespace detail

template<typename F, typename T>
void do_wrapped(F f, const std::function<void (util::async_result<T>)>& handler) {
    try {
        f();
    } catch (...) {
        handler(std::current_exception());
    }
}

template<typename F, typename T = typename detail::arg_type<F>::type, typename H>
typename std::enable_if<!std::is_same<T, void>::value, std::function<void (util::async_result<T>)>>::type wrapped(F f, H handler)
{
    return [=] (util::async_result<T> res) {
        try {
            f(res.get());
        } catch (...) {
            handler(std::current_exception());
        }
    };
}

template<typename F, typename T = typename detail::arg_type<F>::type, typename H>
typename std::enable_if<std::is_same<T, void>::value, std::function<void (util::async_result<T>)>>::type wrapped(F f, H handler)
{
    return [=] (util::async_result<T> res) {
        try {
            res.get();
            f();
        } catch (...) {
            handler(std::current_exception());
        }
    };
}

} } // namespace funtls::util

#endif
