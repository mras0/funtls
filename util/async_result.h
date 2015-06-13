#ifndef UTIL_ASYNC_RESULT_H_INCLUDED
#define UTIL_ASYNC_RESULT_H_INCLUDED

#include <utility>
#include <exception>
#include <new>
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

    union {
        T                  result_;
        std::exception_ptr exception_;
    };

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

} } // namespace funtls::util

#endif
