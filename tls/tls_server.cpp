#include <tls/tls_server.h>
#include <tls/tls_ser.h>
#include <tls/tls_ecc.h>
#include <util/base_conversion.h>
#include <sstream>

// TEMP
#include <iostream>
#include <util/ostream_adapter.h>

using funtls::util::wrapped;

namespace funtls { namespace tls {

class connection_to_client : public tls_base, public std::enable_shared_from_this<connection_to_client> {
public:
    static void make(const std::string& name, std::unique_ptr<stream> stream, const std::vector<const server_id*> server_ids, const client_connect_handler& on_client_connected) {
        auto c = std::shared_ptr<connection_to_client>(new connection_to_client{name, std::move(stream), server_ids, on_client_connected});
        c->read_client_hello();
    }

    ~connection_to_client();
private:
    util::ostream_adapter                           log_;
    std::vector<const server_id*>                   server_ids_;
    client_connect_handler                          on_client_connected_;
    std::unique_ptr<server_key_exchange_protocol>   server_kex_;

    connection_to_client(const std::string& name, std::unique_ptr<stream> stream, const std::vector<const server_id*> server_ids, const client_connect_handler& on_client_connected);

    void read_client_hello();
    void send_server_hello();
    void send_server_certificate();
    void send_server_key_exchange();
    void send_server_hello_done();
    void read_client_key_exchange();

    void handle_error(std::exception_ptr e) const;
};

void perform_handshake_with_client(const std::string& name, std::unique_ptr<stream> stream, const std::vector<const server_id*> server_ids, const client_connect_handler& on_client_connected)
{
    connection_to_client::make(name, std::move(stream), server_ids, on_client_connected);
}

connection_to_client::connection_to_client(const std::string& name, std::unique_ptr<stream> stream, const std::vector<const server_id*> server_ids, const client_connect_handler& on_client_connected)
    : tls_base(std::move(stream), tls_base::connection_end::server)
    , log_([name](const std::string& s) { std::cout << name + ": " + s; })
    , server_ids_(server_ids)
    , on_client_connected_(on_client_connected)
    , server_kex_(nullptr)
{
    log_ << "Connected" << std::endl;
    assert(!server_ids_.empty());
}

connection_to_client::~connection_to_client()
{
    log_ << "Conncetion dropped" << std::endl;
}

void connection_to_client::handle_error(std::exception_ptr e) const
{
    assert(e);
    std::ostringstream msg;
    msg << "[!!!] ";
    try {
        std::rethrow_exception(e);
    } catch (const std::exception& e) {
        msg << e.what();
    } catch (...) {
        msg << "Unknown exception type caught";
    }
    msg << "" << std::endl;
    const_cast<util::ostream_adapter&>(log_) << msg.str(); // Meh...
}


void connection_to_client::read_client_hello() {
    log_ << "Reading ClientHello" << std::endl;
    auto self = shared_from_this();
    read_handshake(wrapped(
        [self](tls::handshake&& handshake) {
        auto client_hello = get_as<tls::client_hello>(handshake);
        self->log_ << "Got client hello" << std::endl;
        self->log_ << "version " << client_hello.client_version << "" << std::endl;
        self->log_ << "session " << util::base16_encode(client_hello.session_id.as_vector()) << "" << std::endl;
        self->log_ << "cipher_suites:";
        for (auto cs : client_hello.cipher_suites.as_vector()) {
            self->log_ << " " << cs;
        }
        self->log_ << "" << std::endl;
        self->log_ << "compression_methods:";
        for (auto cm : client_hello.compression_methods.as_vector()) {
            self->log_ << " " << (int)cm;
        }
        self->log_ << "" << std::endl;
        self->log_ << "extensions:" << std::endl;
        for (const auto& ext : client_hello.extensions) {
            self->log_ << " ";
            switch (ext.type) {
            case extension_type::server_name:
                {
                    auto sne = get_as<server_name_extension>(ext);
                    FUNTLS_CHECK_BINARY(sne.server_name_list.size(), ==, 1, "Invalid server name extension");
                    FUNTLS_CHECK_BINARY(int(sne.server_name_list[0].name_type), ==, int(server_name::server_name_type::host_name), "Invalid server name extension");
                    self->log_ << sne;
                }
                break;
            case extension_type::elliptic_curves:
                self->log_ << get_as<elliptic_curves_extension>(ext);
                break;
            case extension_type::ec_point_formats:
                self->log_ << get_as<ec_point_formats_extension>(ext);
                break;
            case extension_type::signature_algorithms:
                self->log_ << get_as<signature_algorithms_extension>(ext);
                break;
            case extension_type::application_layer_protocol_negotiation:
                self->log_ << get_as<application_layer_protocol_negotiation_extension>(ext);
                break;
            default:
                self->log_ << ext.type << " " << util::base16_encode(ext.data.as_vector());
            }
            self->log_ << std::endl;
        }

        auto cipher = cipher_suite::null_with_null_null;
        // Find the first supported cipher
        for (auto cs : client_hello.cipher_suites.as_vector()) {
            if (is_supported(cs)) {
                const auto kex = parameters_from_suite(cs).key_exchange_algorithm;
                for (auto id : self->server_ids_) {
                    if (id->supports(kex)) {
                        assert(self->server_kex_ == nullptr);
                        cipher            = cs;
                        self->server_kex_ = id->key_exchange_protocol(kex);
                        break;
                    }
                }
            }
            if (cipher != cipher_suite::null_with_null_null) {
                break;
            }
        }
        FUNTLS_CHECK_BINARY(client_hello.client_version, >=, tls::protocol_version_tls_1_2, "Invalid protocol version");
        FUNTLS_CHECK_BINARY(cipher, !=, cipher_suite::null_with_null_null, "No common cipher found");
        self->current_protocol_version(tls::protocol_version_tls_1_2);
        self->client_random(client_hello.random);
        self->negotiated_cipher(cipher);
        // TODO: Check that "No compression" is supported
        self->log_ << "Negotatiated cipher: " << cipher << std::endl;
        assert(self->server_kex_);

        self->send_server_hello();
    },
        std::bind(&connection_to_client::handle_error, self, std::placeholders::_1)));
}

void connection_to_client::send_server_hello()
{
    log_ << "Sending ServerHello" << std::endl;
    auto self = shared_from_this();
    send_handshake(make_handshake(
        server_hello{
        current_protocol_version(),
        server_random(),
        session_id(),
        negotiated_cipher(),
        compression_method::null,
        std::vector<extension>{}
    }), wrapped([self]() {
        self->send_server_certificate();
    }, std::bind(&connection_to_client::handle_error, self, std::placeholders::_1)));
}

void connection_to_client::send_server_certificate()
{
    const auto chain = server_kex_->certificate_chain();
    if (chain) {
        log_ << "Sending ServerCertificate" << std::endl;
        auto self = shared_from_this();
        send_handshake(make_handshake(
            certificate{*chain}), wrapped([self]() {
            self->send_server_key_exchange();
        }, std::bind(&connection_to_client::handle_error, self, std::placeholders::_1)));
    } else {
        send_server_key_exchange();
    }
}

void connection_to_client::send_server_key_exchange()
{
    if (auto handshake = server_kex_->server_key_exchange(client_random(), server_random())) {
        log_ << "Sending ServerKeyExchange" << std::endl;
        auto self = shared_from_this();
        send_handshake(*handshake, wrapped([self]() {
            self->send_server_hello_done();
        }, std::bind(&connection_to_client::handle_error, self, std::placeholders::_1)));
    } else {
        send_server_hello_done();
    }
}

void connection_to_client::send_server_hello_done()
{
    log_ << "Sending ServerHelloDone" << std::endl;
    auto self = shared_from_this();
    send_handshake(make_handshake(
        server_hello_done{}), wrapped([self]() {
        self->read_client_key_exchange();
    }, std::bind(&connection_to_client::handle_error, self, std::placeholders::_1)));
}

void connection_to_client::read_client_key_exchange() {
    log_ << "Reading ClientKeyExchange" << std::endl;
    auto self = shared_from_this();
    read_handshake(wrapped(
        [self](tls::handshake&& handshake) {
        auto pre_master_secret = self->server_kex_->client_key_exchange(handshake);
        //self->log_ << "Premaster secret: " << util::base16_encode(pre_master_secret) << std::endl;
        self->set_pending_ciphers(pre_master_secret);
        self->log_ << "Reading ChangeCipherSpec" << std::endl;
        self->read_change_cipher_spec(wrapped(
            [self]() {
            self->log_ << "Sending ChangeCipherSpec" << std::endl;
            self->send_change_cipher_spec(wrapped(
                [self]() {
                self->log_ << "Handshake done. Session id " << util::base16_encode(self->session_id().as_vector()) << std::endl;
                self->on_client_connected_(std::shared_ptr<tls_base>{self});
            },
                std::bind(&connection_to_client::handle_error, self, std::placeholders::_1)));
        },
            std::bind(&connection_to_client::handle_error, self, std::placeholders::_1)));
    },
        std::bind(&connection_to_client::handle_error, self, std::placeholders::_1)));
}

} } // namespace funtls::tls
