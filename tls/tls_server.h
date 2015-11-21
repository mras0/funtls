#ifndef FUNTLS_TLS_TLS_SERVER_H_INCLUDED
#define FUNTLS_TLS_TLS_SERVER_H_INCLUDED

#include <tls/tls_base.h>
#include <util/async_result.h>

namespace funtls { namespace tls {

class server_key_exchange_protocol {
public:
    virtual ~server_key_exchange_protocol() {}

    // returns nullptr if no ServerCertificate message should be sent, a list of certificates to send otherwise
    const std::vector<asn1cert>* certificate_chain() const {
        return do_certificate_chain();
    }

    // returns nullptr if no ServerKexEchange message should be sent, the appropriate handshake otherwise
    std::unique_ptr<handshake> server_key_exchange(const random& client_random, const random& server_random) const {
        return do_server_key_exchange(client_random, server_random);
    }

    // returns the master secret, the handshake is the ClientKeyExchange message received from the client
    std::vector<uint8_t> client_key_exchange(const handshake& handshake) const {
        return do_client_key_exchange(handshake);
    }

private:
    virtual const std::vector<asn1cert>* do_certificate_chain() const = 0;
    virtual std::unique_ptr<handshake> do_server_key_exchange(const random& client_random, const random& server_random) const = 0;
    virtual std::vector<uint8_t> do_client_key_exchange(const handshake&) const = 0;
};

class server_id {
public:
    virtual ~server_id() {}

    // returns true if the server identification supports the key exchange algorithm
    bool supports(key_exchange_algorithm kex_algo) const {
        return do_supports(kex_algo);
    }

    // creates server kex echange protocol object for the given key exchange algoithm (the client of this class must check that the server_id `supports` the kex_algo)
    std::unique_ptr<server_key_exchange_protocol> key_exchange_protocol(key_exchange_algorithm kex_algo) const {
        return do_key_exchange_protocol(kex_algo);
    }
private:
    virtual bool do_supports(key_exchange_algorithm) const = 0;
    virtual std::unique_ptr<server_key_exchange_protocol> do_key_exchange_protocol(key_exchange_algorithm) const = 0;
};

using client_connect_handler = std::function<void(util::async_result<std::shared_ptr<tls_base>>)>;

void perform_handshake_with_client(const std::string& name, std::unique_ptr<stream> stream, const std::vector<const server_id*> server_ids, const client_connect_handler& on_client_connected);

} } // namespace funtls::tls

#endif
