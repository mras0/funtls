#ifndef FUNTLS_TCP_TLS_SERVER_H_INCLUDED
#define FUNTLS_TCP_TLS_SERVER_H_INCLUDED

#include <memory>
#include <functional>
#include <tls/tls_server.h>
#include <boost/asio.hpp>

namespace funtls {

class tcp_tls_server : public std::enable_shared_from_this<tcp_tls_server> {
public:
    using log_ptr              = std::shared_ptr<std::ostream>;
    using log_factory_function = std::function<log_ptr (const std::string& /*name*/)>;
    using on_accept_function   = std::function<void (util::async_result<std::shared_ptr<tls::tls_base>>, const log_ptr&)>;

    ~tcp_tls_server();

    static std::shared_ptr<tcp_tls_server> create(boost::asio::io_service& io_service, const boost::asio::ip::tcp::endpoint& local_endpoint, std::unique_ptr<tls::server_id> server_id, const log_factory_function& log_factory, const on_accept_function& on_accept) {
        auto server = std::shared_ptr<tcp_tls_server>{new tcp_tls_server{io_service, local_endpoint, std::move(server_id), log_factory, on_accept}};
        server->start_accept();
        return server;
    }

    boost::asio::ip::tcp::endpoint local_endpoint() const {
        return acceptor_.local_endpoint();
    }

private:
    boost::asio::ip::tcp::acceptor  acceptor_;
    std::unique_ptr<tls::server_id> server_id_;
    log_factory_function            log_factory_;
    on_accept_function              on_accept_;
    log_ptr                         main_log_;

    tcp_tls_server(boost::asio::io_service& io_service, const boost::asio::ip::tcp::endpoint& local_endpoint, std::unique_ptr<tls::server_id> server_id, const log_factory_function& log_factory, const on_accept_function& on_accept);

    void start_accept();
};

} // namespace funtls

#endif