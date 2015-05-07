#ifndef FUNTLS_X509_X509_EC_H_INCLUDED
#define FUNTLS_X509_X509_EC_H_INCLUDED

#include <x509/x509.h>

namespace funtls { namespace x509 {

static const asn1::object_id id_secp384r1{1,3,132,0,34};

void verify_x509_signature_ec(const certificate& subject_cert, const certificate& issuer_cert);

} } // namespace funtls::x509

#endif
