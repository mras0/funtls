#include "trust_store_win32.h"
#include <util/win32_util.h>
#include <cassert>
#include <memory>
#include <system_error>

#include <windows.h>
#pragma comment(lib, "crypt32.lib")

using namespace funtls;

namespace {

// http://stackoverflow.com/questions/7781898/get-an-istream-from-a-char
struct membuf : std::streambuf {
    membuf(void* begin, size_t size) {
        this->setg(static_cast<char*>(begin), static_cast<char*>(begin), static_cast<char*>(begin) + size);
    }
};

struct CertStoreCloser {
    using pointer = HCERTSTORE;
    void operator()(pointer p) { assert(p); CertCloseStore(p, 0); }
};

using cert_store = std::unique_ptr<HCERTSTORE, CertStoreCloser>;

std::string name_blob_to_string(DWORD dwCertEncodingType, PCERT_NAME_BLOB pName) {
    std::string name(pName->cbData, L'\0');
    const DWORD cch = CertNameToStrA(dwCertEncodingType, pName, CERT_X500_NAME_STR, &name[0], static_cast<DWORD>(name.size()));
    if (!cch) util::throw_system_error("Could not convert certificate name to string");
    name.resize(cch - 1);
    return name;
}


} // unnamed namespace

namespace funtls { namespace x509 {

std::vector<x509::certificate> win32_root_certificates()
{
    cert_store store{CertOpenSystemStore(0, L"ROOT")};
    if (!store) {
        util::throw_system_error("Could not open root certificate store");
    }

    //certificate read_pem_certificate(std::istream& is);
    std::vector<x509::certificate> certs;

    for (PCCERT_CONTEXT cert_context = nullptr; (cert_context = CertEnumCertificatesInStore(store.get(), cert_context)) != nullptr;) {
        if (cert_context->dwCertEncodingType != X509_ASN_ENCODING) {
            throw std::runtime_error("Unsupported certificate encoding encountered: " + std::to_string(cert_context->dwCertEncodingType));
        }
        
        util::buffer_view cert_buf(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
        certs.push_back(certificate::parse(asn1::read_der_encoded_value(cert_buf)));
    }

    return certs;
}

} } // namespace funtls::x509

