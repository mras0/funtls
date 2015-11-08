#include <iostream>
#include <fstream>
#include <string>
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

void make()
{
    const auto serial_number  = asn1::integer::from_bytes({0x01});
    const auto signature_algo = x509::algorithm_id{x509::id_sha256WithRSAEncryption};
    x509::name subject{{std::make_pair(x509::attr_commonName, asn1::ia5_string{"localhost"})}};

    const asn1::utc_time not_before{""};
    const asn1::utc_time not_after{""};
    const asn1::bit_string subject_public_key{std::vector<uint8_t>{1,2,3}};

    x509::tbs_certificate cert {
        x509::version::v3,
        serial_number,
        signature_algo, // signature_algorithm
        subject, // issuer
        not_before,
        not_after,
        subject, // subect
        signature_algo, // subject_public_key_algo
        subject_public_key,
        {} // extensions
    };
    std::cout << cert << std::endl;
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
