#ifndef TLS_KEX_H_INCLUDED
#define TLS_KEX_H_INCLUDED

#include "tls.h"
#include <x509/x509.h>

namespace funtls { namespace tls {

class client_key_exchange_protocol {
public:
    // shared secret, handshake
    typedef std::pair<std::vector<uint8_t>, handshake> result_type;

    virtual ~client_key_exchange_protocol() {}

    result_type result() const {
        return do_result();
    }

    void certificate_list(const std::vector<x509::certificate>& certificate_list);
    void server_key_exchange(const handshake& ske) {
        do_server_key_exchange(ske);
    }

protected:
    const x509::certificate& server_certificate() const;

private:
    std::unique_ptr<x509::certificate> server_certificate_;

    virtual result_type do_result() const = 0;
    virtual void do_server_key_exchange(const handshake&);
};

std::unique_ptr<client_key_exchange_protocol> make_client_key_exchange_protocol(key_exchange_algorithm kex_algo, protocol_version ver, const random& client_random, const random& server_random);

} } // namespace funtls

#endif
