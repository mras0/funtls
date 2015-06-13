#ifndef ASIO_STREAM_ADAPTER_H_INCLUDED
#define ASIO_STREAM_ADAPTER_H_INCLUDED

#include <memory>

#include <tls/tls_base.h>
#include <boost/asio.hpp>

namespace funtls {

template<typename S>
class asio_stream_adapter : public tls::stream {
public:
    explicit asio_stream_adapter(S&& s) : s_(std::move(s)) {
    }

private:
    S s_;

    virtual void do_read(std::vector<uint8_t>& buf, const tls::done_handler& handler) override {
        boost::asio::async_read(s_, boost::asio::buffer(buf),
            [handler](const boost::system::error_code& ec, size_t) { complete(ec, handler); });
    }

    virtual void do_write(const std::vector<uint8_t>& buf, const tls::done_handler& handler) override {
        boost::asio::async_write(s_, boost::asio::buffer(buf),
            [handler](const boost::system::error_code& ec, size_t) { complete(ec, handler); });
    }

    static void complete(const boost::system::error_code& ec, const tls::done_handler& handler) {
        if (ec) {
            handler(make_exception(ec));
        } else {
            handler(util::async_result<void>());
        }
    }

    static std::exception_ptr make_exception(boost::system::error_code ec) {
        return std::make_exception_ptr(boost::system::system_error(ec));
    }
};

template<typename S>
std::unique_ptr<tls::stream> make_tls_stream(S&& s)
{
    return std::unique_ptr<tls::stream>(new asio_stream_adapter<S>(std::move(s)));
}

}

#endif
