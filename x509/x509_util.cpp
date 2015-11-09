#include <iostream>
#include <fstream>
#include <string>
#include <util/base_conversion.h>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <x509/x509_io.h>

using namespace funtls;

void show(const std::string& filename)
{
    std::ifstream in(filename, std::ifstream::binary);
    if (!in || !in.is_open()) {
        throw std::runtime_error("Error opening " + filename);
    }
    std::cout << filename << std::endl;
    while (in && in.peek() != std::char_traits<char>::eof()) {
        auto cert = x509::read_pem_certificate(in);
        std::cout << cert << std::endl;
        if (cert.tbs().issuer == cert.tbs().subject) {
            std::cout << "Verifying self-signed certificate..." << std::flush;
            verify_x509_signature(cert, cert);
            std::cout << "OK\n";
        }
    }
}

class test_certificate_signer : public x509::certificate_signer {
public:
    test_certificate_signer() {}

private:
    virtual std::vector<uint8_t> do_sign(const std::vector<uint8_t>&) const override {
        std::cout << "test_certificate_signer::do_sign ignoring data\n";
        return {0};
    }
    virtual x509::algorithm_id do_algorithm_id() const override {
        return x509::algorithm_id{x509::id_sha256WithRSAEncryption};
    }
};


void make()
{
    x509::name subject{{std::make_pair(x509::attr_commonName, asn1::ia5_string{"localhost"})}};
    
    const asn1::utc_time not_before{"1511080000Z"};
    const asn1::utc_time not_after{"2511080000Z"};
    const asn1::bit_string subject_public_key{std::vector<uint8_t>{1,2,3}};

    x509::tbs_certificate tbs{
        x509::version::v3,                                    // version
        asn1::integer::from_bytes({0x01}),                    // serial_number
        x509::algorithm_id{x509::id_sha256WithRSAEncryption}, // signature_algorithm
        subject,                                              // issuer
        not_before,                                           // validity_not_before
        not_after,                                            // validity_not_after
        subject,                                              // subect
        x509::algorithm_id{x509::id_rsaEncryption},           // subject_public_key_algo
        subject_public_key,                                   // subject_public_key
        {} // extensions
    };


    auto cert = test_certificate_signer{}.sign(tbs);
    std::cout << cert << std::endl;
    x509::verify_x509_signature(cert, cert);
}

int main(int argc, char** argv)
{
    auto usage = [program_name = argv[0]] {
        std::cout << "Usage: " << program_name << " <command> [<args>]\n";
        std::cout << "Commands:\n";
        std::cout << "   show <certificate file>  Show certificate\n";
        std::cout << "   make                     Make certificate [Experimental]\n";
        exit(1);
    };

    auto consume_argv = [&argc, &argv, &usage] {
        if (argc < 1) {
            usage();
        }
        const char* const arg = argv[0];
        argv++;
        argc--;
        return arg;
    };

    consume_argv();
    const std::string command = consume_argv();

    try {
        if (command == "show") {
            show(consume_argv());
        } else if (command == "make") {
            make();
        } else {
            std::cout << "Unknown command '" << command << "'\n";
            usage();
        }
    } catch (const std::runtime_error& e) {
        std::cout << e.what() << "\n";
    }
}
