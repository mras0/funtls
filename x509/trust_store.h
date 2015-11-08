#ifndef FUNTLS_X509_TRUST_STORE_H_INCLUDED
#define FUNTLS_X509_TRUST_STORE_H_INCLUDED

#include <x509/x509.h>

namespace funtls { namespace x509 {
class trust_store {
public:
    trust_store() : log_(nullptr) {}

    void set_log(std::ostream& log) { log_ = &log; }

    void add(const x509::certificate& cert);
    void add_from_directory(const std::string& path);
    void add_all_from_file(const std::string& filename);
    void add_os_defaults();

    std::vector<const x509::certificate*> find(const x509::name& subject_name) const;

    void verify_cert_chain(const std::vector<x509::certificate>& certlist) const;
private:
    std::ostream*                  log_;
    std::vector<x509::certificate> certs_;
};

} } // namespace funtls::x509

#endif
