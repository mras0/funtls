#ifndef FUNTLS_X509_TRUST_STORE_WIN32_H_INCLUDED
#define FUNTLS_X509_TRUST_STORE_WIN32_H_INCLUDED

#include <x509/x509.h>
#include <vector>

namespace funtls { namespace x509 {

std::vector<x509::certificate> win32_root_certificates();

} } // namespace funtls::x509

#endif

