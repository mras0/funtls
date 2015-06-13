#ifndef FUNTLS_TLS_TLS_BASE_H_INCLUDED
#define FUNTLS_TLS_TLS_BASE_H_INCLUDED

#include <tls/tls.h>
#include <util/async_result.h>

namespace funtls { namespace x509 {
struct certificate;
} }

namespace funtls { namespace tls {

using app_data_sent_handler         = std::function<void (util::async_result<void>)>;
using app_data_handler              = std::function<void (util::async_result<std::vector<uint8_t>>)>;
using done_handler                  = std::function<void(util::async_result<void>)>;
using verify_certificate_chain_func = std::function<void (const std::vector<x509::certificate>&)>;

class cipher;

class stream {
public:
    virtual ~stream() {}

    // buf must be valid (and unchanged) until handler is called
    void read(std::vector<uint8_t>& buf, const done_handler& handler) {
        do_read(buf, handler);
    }

    // buf must be kept alive until handler is called
    void write(const std::vector<uint8_t>& buf, const done_handler& handler) {
        do_write(buf, handler);
    }

private:
    virtual void do_read(std::vector<uint8_t>& buf, const done_handler& handler) = 0;
    virtual void do_write(const std::vector<uint8_t>& buf, const done_handler& handler) = 0;
};

// TODO: Handle record fragmentation/coalescence
class tls_base {
public:
    void send_app_data(const std::vector<uint8_t>& d, const app_data_sent_handler& handler);
    void recv_app_data(const app_data_handler& handler);

protected:
    enum class connection_end { server, client };

    using recv_record_handler    = std::function<void(util::async_result<record>)>;
    using recv_handshake_handler = std::function<void(util::async_result<handshake>)>;

    explicit tls_base(std::unique_ptr<stream> stream, connection_end ce) : stream_(std::move(stream)), connection_end_(ce) {
        assert(stream_);
    }

    ~tls_base();

    void send_record(tls::content_type content_type, const std::vector<uint8_t>& plaintext, const done_handler& handler);
    void recv_record(const recv_record_handler& handler);
    void send_handshake(const handshake& handshake, const done_handler& handler);
    void read_handshake(const recv_handshake_handler& handler);

    protocol_version current_protocol_version() const {
        return current_protocol_version_;
    }

    std::vector<uint8_t> handshake_messages() const {
        return handshake_messages_;
    }

    void set_pending_ciphers(cipher_parameters&& client_cipher_parameters, cipher_parameters&& server_cipher_parameters);

    void send_change_cipher_spec(const done_handler& handler);
    void read_change_cipher_spec(const done_handler& handler);

    void do_read_finished(const done_handler& handler);

private:
    std::unique_ptr<stream>      stream_;
    // State
    connection_end               connection_end_;
    protocol_version             current_protocol_version_ = protocol_version_tls_1_2;
    uint64_t                     encrypt_sequence_number_  = 0;
    uint64_t                     decrypt_sequence_number_  = 0;
    std::unique_ptr<cipher>      encrypt_cipher_           = make_cipher(null_cipher_parameters_e);
    std::unique_ptr<cipher>      decrypt_cipher_           = make_cipher(null_cipher_parameters_d);
    std::unique_ptr<cipher>      pending_encrypt_cipher_;
    std::unique_ptr<cipher>      pending_decrypt_cipher_;
    std::vector<uint8_t>         handshake_messages_;
    std::vector<uint8_t>         pending_handshake_messages_;

    std::vector<uint8_t>         send_buffer_;
    std::vector<uint8_t>         recv_buffer_;

    void collapse_pending();
    void do_recv_record_content(const recv_record_handler& handler);
    void do_decrypt(tls::content_type content_type, tls::protocol_version protocol_version, const recv_record_handler& handler);
    void send_finished(const done_handler& handler);

    virtual std::vector<uint8_t> do_verify_data(tls::tls_base::connection_end ce) const = 0;
};
} } // namespace funtls::tls

#endif
