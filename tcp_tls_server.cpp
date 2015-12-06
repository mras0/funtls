#include "tcp_tls_server.h"
#include "asio_stream_adapter.h"

namespace funtls {

tcp_tls_server::tcp_tls_server(boost::asio::io_service& io_service, const boost::asio::ip::tcp::endpoint& local_endpoint, std::unique_ptr<tls::server_id> server_id, const log_factory_function& log_factory, const on_accept_function& on_accept)
    : acceptor_(io_service, local_endpoint)
    , server_id_(std::move(server_id))
    , log_factory_(log_factory)
    , on_accept_(on_accept)
    , main_log_(log_factory_("tcp_tls_server")) {
}

tcp_tls_server::~tcp_tls_server() = default;


void tcp_tls_server::start_accept() {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_io_service());
    auto self = shared_from_this();
    acceptor_.async_accept(*socket,
        [self, socket] (const boost::system::error_code& ec) {
        if (ec) {
            (*self->main_log_) << "Accept failed: " << ec << std::endl;
        } else {
            std::ostringstream oss;
            oss << socket->remote_endpoint();
            auto log = self->log_factory_(oss.str());
            assert(socket.use_count() == 1);
            tls::perform_handshake_with_client(make_tls_stream(std::move(*socket)), {self->server_id_.get()}, std::bind(self->on_accept_, std::placeholders::_1, log), log.get());
        }
        self->start_accept();
    });
}

} // namespace funtls