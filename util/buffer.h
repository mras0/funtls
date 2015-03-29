#ifndef FUNTLS_UTIL_BUFFER_H_INCLUDED
#define FUNTLS_UTIL_BUFFER_H_INCLUDED

#include <stdint.h>
#include <cassert>
#include <stdexcept>
#include <cstring>

namespace funtls { namespace util {

struct buffer_view {
    buffer_view(const uint8_t* buffer, size_t size) : buffer_(buffer), size_(size), index_(0) {
    }

    size_t index() const {
        return index_;
    }

    size_t size() const {
        return size_;
    }

    size_t remaining() const {
        assert(index_ <= size_);
        return size_ - index_;
    }

    void skip(size_t num_bytes) {
        if (index_ + num_bytes > size_) throw std::runtime_error("Out of data in " + std::string(__PRETTY_FUNCTION__));
        index_ += num_bytes;
    }

    uint8_t get() {
        uint8_t res;
        read(&res, 1);
        return res;
    }

    void read(void* dest, size_t num_bytes) {
        if (index_ + num_bytes > size_) throw std::runtime_error("Out of data in " + std::string(__PRETTY_FUNCTION__));
        std::memcpy(dest, &buffer_[index_], num_bytes);
        index_ += num_bytes;
    }

    buffer_view get_slice(size_t slice_size) {
        if (index_ + slice_size > size_) throw std::runtime_error("Out of data in " + std::string(__PRETTY_FUNCTION__));
        const uint8_t* slice_buffer = buffer_ + index_;
        index_ += slice_size;
        return buffer_view(slice_buffer, slice_size);
    }

private:
    const uint8_t* buffer_;
    size_t         size_;
    size_t         index_;
};

} } // namespace funtls::util

#endif
