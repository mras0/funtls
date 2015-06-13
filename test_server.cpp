#include <iostream>
#include <stdio.h> // popen

#include <util/test.h>
#include <tls/tls_base.h>
#include <asio_stream_adapter.h>

using namespace funtls;
using util::async_result;
using util::wrapped;
using util::do_wrapped;

namespace funtls { namespace tls {

class connection : public tls_base, public std::enable_shared_from_this<connection> {
public:
    using ptr_t = std::shared_ptr<connection>;

    static ptr_t make(const std::string& name, std::unique_ptr<stream> stream) {
        auto c = ptr_t(new connection{name, std::move(stream)});
        c->read_client_hello();
        return c;
    }

    ~connection();
private:
    std::string name_;

    connection(const std::string& name, std::unique_ptr<stream> stream);

    void read_client_hello();

    void handle_error(std::exception_ptr e) const;

    virtual std::vector<uint8_t> do_verify_data(tls_base::connection_end ce) const override {
        (void)ce;
        FUNTLS_CHECK_FAILURE("Not implemented");
    }
};

connection::connection(const std::string& name, std::unique_ptr<stream> stream)
    : tls_base(std::move(stream), tls_base::connection_end::server)
    , name_(name)
{
    std::cout << name_ << ": Connected\n";
}

connection::~connection()
{
    std::cout << name_ << ": Conncetion dropped\n";
}

void connection::handle_error(std::exception_ptr e) const
{
    assert(e);
    std::ostringstream msg;
    msg << name_ << ": ";
    msg << "[!!!] ";
    try {
        std::rethrow_exception(e);
    } catch (const std::exception& e) {
        msg << e.what();
    } catch (...) {
        msg << "Unknown exception type caught";
    }
    msg << "\n";
    std::cerr << msg.str();
}


void connection::read_client_hello() {
    std::cout << name_ << ": Reading client hello\n";
    auto self = shared_from_this();
    read_handshake(wrapped(
            [self] (tls::handshake&& handshake) {
                std::cout << "GOT HANDSHAKE OF TYPE " << handshake.type << std::endl;
            },
            std::bind(&connection::handle_error, self, std::placeholders::_1)));
}

} } // namespace funtls::tls

#include <thread>

int main()
{
    boost::asio::io_service        io_service;
    boost::asio::ip::tcp::acceptor acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
    unsigned short port = acceptor.local_endpoint().port();

    struct accept_state {
        accept_state(boost::asio::io_service& io_service) : socket(io_service) {
        }
        boost::asio::ip::tcp::socket socket;
    };

    std::function<void (void)> start_accept = [&acceptor, &start_accept] {
        auto state = std::make_shared<accept_state>(acceptor.get_io_service());
        acceptor.async_accept(state->socket,
            [state, start_accept] (const boost::system::error_code& ec) {
                if (ec) {
                    std::cout << "Accept failed: " << ec << std::endl;
                } else {
                    std::ostringstream oss;
                    oss << state->socket.remote_endpoint();
                    tls::connection::make(oss.str(), make_tls_stream(std::move(state->socket)));
                }
                std::cout << "Not calling start_accept in " << __FILE__ << " " << __LINE__ << std::endl;
                //start_accept();
            });
    };

    start_accept();
    std::cout << "Server running: " << acceptor.local_endpoint() << std::endl;

    std::thread client_thread([port, &io_service] {
            boost::asio::io_service::work work(io_service); // keep the io_service running as long as the thread does
            std::ostringstream cmd;
            cmd << "openssl s_client -connect localhost:" << port << " 2>&1";
            io_service.post([&] {
                    std::cout << "Running command: " << cmd.str() << std::endl;
                    });
            std::unique_ptr<FILE, decltype(&::fclose)> f{popen(cmd.str().c_str(), "r"), &::fclose};
            assert(f);
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), f.get())) {
                std::string s=buffer;
                io_service.post([s] {
                        std::cout << "[openssh] " << s;
                        });
            }
        });

    io_service.run();
    client_thread.join();
    return 0;
}

