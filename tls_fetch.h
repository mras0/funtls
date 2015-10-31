#ifndef FUNTLS_TLS_FETCH_H_INCLUDED
#define FUNTLS_TLS_FETCH_H_INCLUDED

#include <tls/tls_client.h>
#include <x509/trust_store.h>

namespace funtls {

void tls_fetch(const std::string& host, const std::string& port, const std::string& path, const std::vector<tls::cipher_suite>& wanted_ciphers, const x509::trust_store& ts, std::function<void (const std::vector<uint8_t>&)> on_data);

} // namespace funtls

#endif
