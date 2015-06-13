#include <x509/trust_store.h>
#include <x509/x509_io.h>
#include <util/test.h>

#include <memory>
#include <fstream>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

#include <iostream>

namespace {

std::vector<std::string> all_files_in_dir(const std::string& dir)
{
    std::unique_ptr<DIR, decltype(&::closedir)> dir_(opendir(dir.c_str()), &::closedir);
    if (!dir_) {
        throw std::runtime_error("opendir('" + dir + "') failed: " + strerror(errno));
    }

    std::vector<std::string> files;
    while (dirent* de = readdir(dir_.get())) {
        if (de->d_name[0] == '.') {
            continue;
        }
        const auto p = dir + "/" + de->d_name;
        struct stat st;
        if (stat(p.c_str(), &st) < 0) {
            throw std::runtime_error("stat('" + p + "') failed: " + strerror(errno));
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        files.push_back(p);
    }
    return files;
}

} // unnamed namespace
namespace funtls { namespace x509 {

void trust_store::add(const x509::certificate& cert)
{
    certs_.push_back(cert);
}

std::vector<const x509::certificate*> trust_store::find(const x509::name& subject_name) const {
    std::vector<const x509::certificate*> res;
    for (const auto& cert : certs_) {
        if (cert.tbs().subject == subject_name) {
            try {
                x509::verify_x509_signature(cert, cert);
                res.push_back(&cert);
            } catch (const std::exception& e) {
                std::cout << cert << "Not used: " << e.what() << std::endl;
            }
        }
    }
    return res;
}

void trust_store::add_from_directory(const std::string& path)
{
    std::cout << "Adding certificates to trust store from " << path << std::endl;
    for (const auto& f : all_files_in_dir(path)) {
        assert(f.size() > path.size() + 1);
        const auto fn = f.substr(path.size()+1);
        std::cout << " " << fn << " ... " << std::flush;
        if (fn == "ca-certificates.crt") {
            std::cout << "HACK - skipping\n";
            continue;
        }
        auto cert = x509::read_pem_certificate_from_file(f);
        add(cert);
        std::cout << cert.tbs().subject << std::endl;
    }
}

void trust_store::add_all_from_file(const std::string& filename)
{
    std::ifstream in(filename, std::ifstream::binary);
    if (!in || !in.is_open()) throw std::runtime_error("Error opering " + filename);

    while (in && in.peek() != std::char_traits<char>::eof()) {
        auto cert = x509::read_pem_certificate(in);
        add(cert);
    }

    if (!in) throw std::runtime_error("Error reading from " + filename);
}

void trust_store::verify_cert_chain(const std::vector<x509::certificate>& certlist) const
{
    FUNTLS_CHECK_BINARY(certlist.size(), >, 0, "Empty certificate chain not allowed");
    const auto self_signed = certlist.back().tbs().subject == certlist.back().tbs().issuer;
    if (certlist.size() == 1 && self_signed) {
        std::cout << "Checking self-signed certificate\n" << certlist[0] << std::endl;
        x509::verify_x509_signature(certlist[0], certlist[0]);
        return;
    }
    auto complete_chain = certlist;
    if (!self_signed) {
        const auto root_issuer_name = certlist.back().tbs().issuer;
        // Incomplete chain, try to locate root certificate
        auto certs = find(root_issuer_name);
        if (certs.empty()) {
            std::ostringstream oss;
            oss << "No valid certificate found in trust store for " << root_issuer_name;
            FUNTLS_CHECK_FAILURE(oss.str());
        }
        const x509::certificate* cert = nullptr;
        for (const auto& c : certs) {
            verify_x509_signature(*c, *c);
            if (!cert) {
                cert = c;
            } else {
                std::cout << "Warning multiple certificates could be used for " << c->tbs().subject << std::endl;
            }
        }
        if (!cert) {
            std::ostringstream oss;
            oss << "No valid certificate found in trust store for " << root_issuer_name;
            FUNTLS_CHECK_FAILURE(oss.str());
        }
        complete_chain.push_back(*cert);
    }
    std::cout << "Verifying trust chain:\n";
    for (const auto& cert : complete_chain) std::cout << cert << std::endl << std::endl;
    x509::verify_x509_certificate_chain(complete_chain);
}

} } // namespace funtls::x509
