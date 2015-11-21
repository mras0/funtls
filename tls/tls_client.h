#ifndef FUNTLS_TLS_TLS_CLIENT_H_INCLUDED
#define FUNTLS_TLS_TLS_CLIENT_H_INCLUDED

#include <tls/tls_base.h>

namespace funtls { namespace tls {

class client_key_exchange_protocol;

class client : public tls_base {
public:
    explicit client(std::unique_ptr<stream> stream, const std::vector<cipher_suite>& wanted_ciphers, const verify_certificate_chain_func& verify_certificate_chain);
    ~client();

    void perform_handshake(const done_handler& handler);

private:
    std::vector<cipher_suite>                     wanted_ciphers_;
    verify_certificate_chain_func                 verify_certificate_chain_;
    std::unique_ptr<client_key_exchange_protocol> client_kex;

    void send_client_hello(const done_handler& handler);
    void read_server_hello(const done_handler& handler);
    void read_next_server_handshake(const std::vector<handshake_type>& allowed_handshakes, const done_handler& handler);
    void request_cipher_change(const std::vector<uint8_t>& pre_master_secret, const done_handler& handler);
    void send_client_key_exchange(const done_handler& handler);
};

} } // namespace funtls::tls

#endif
