#ifndef FUNTLS_TLS_TLS_SERVER_RSA_KEX_H_INCLUDED
#define FUNTLS_TLS_TLS_SERVER_RSA_KEX_H_INCLUDED

#include <tls/tls_server.h>
#include <x509/x509_rsa.h>
#include <memory>

namespace funtls { namespace tls {

std::unique_ptr<server_id> make_rsa_server_id(const std::vector<asn1cert>& certificate_chain, x509::rsa_private_key&& private_key);

} } // namespace funtls::tls

#endif
