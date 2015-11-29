#include <iostream>
#include <fstream>
#include <string>
#include <util/base_conversion.h>
#include <util/test.h>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <x509/x509_io.h>

using namespace funtls;

void show_certificate(const std::string& filename)
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

void make_rsa_private_key(unsigned bit_count)
{
    x509::write_pem_private_key_info(std::cout, make_private_key_info(x509::rsa_private_key::generate(bit_count)));
    std::cout << "\n";
}

void make_certificate()
{
    const auto private_key = x509::rsa_private_key::generate(1024);
    const asn1::object_id algo_id{x509::id_sha256WithRSAEncryption};

    {
        std::cout << "Private Key:\n";
        const auto s=util::base64_encode(asn1::serialized(x509::make_private_key_info(private_key)));
        for (size_t i = 0, sz=s.size(); i < sz; ++i) {
            if (i && (i % 64 == 0)) std::cout << '\n';
            std::cout << s[i];
        }
        std::cout << std::endl;
    }

    const x509::name subject{{std::make_pair(x509::attr_commonName, asn1::ia5_string{"localhost"})}};
    const asn1::utc_time not_before{"1511080000Z"};
    const asn1::utc_time not_after{"2511080000Z"};
    const asn1::bit_string subject_public_key_bs{asn1::serialized(x509::rsa_public_key::from_private(private_key))};

    x509::tbs_certificate tbs{
        x509::version::v3,                                    // version
        asn1::integer(1),                                     // serial_number
        x509::algorithm_id{algo_id},                          // signature_algorithm
        subject,                                              // issuer
        not_before,                                           // validity_not_before
        not_after,                                            // validity_not_after
        subject,                                              // subect
        x509::algorithm_id{x509::id_rsaEncryption},           // subject_public_key_algo
        subject_public_key_bs,                                // subject_public_key
        {}                                                    // extensions
    };

    auto cert = x509::rsa_certificate_signer{algo_id, private_key}.sign(tbs);
    std::cout << cert << std::endl;
    x509::verify_x509_signature(cert, cert);
    x509::write_pem_certificate(std::cout, asn1::serialized(cert));
    std::cout << "\n";
}

int main(int argc, char** argv)
{
    auto usage = [program_name = argv[0]] {
        std::cout << "Usage: " << program_name << " <command> [<args>]\n";
        std::cout << "Commands:\n";
        std::cout << "   show-cert <certificate file>  Show certificate\n";
        std::cout << "   make-cert                     Make certificate ((Experimental))\n";
        std::cout << "   make-rsa-private-key          Make RSA private key [bits] ((Experimental))\n";
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
        if (command == "show-cert") {
            show_certificate(consume_argv());
        } else if (command == "make-cert") {
            make_certificate();
        } else if (command == "make-rsa-private-key") {
            unsigned bits = 512;
            if (argc >= 1) {
                const auto arg = consume_argv();
                std::istringstream iss(arg);
                if (!(iss >> bits) || bits < 10 || bits > 4096) {
                    std::cerr << "Invalid bit count " << bits << std::endl;
                    usage();
                }
            }
            make_rsa_private_key(bits);
        } else {
            std::cout << "Unknown command '" << command << "'\n";
            usage();
        }
    } catch (const std::runtime_error& e) {
        std::cout << e.what() << "\n";
    }
}
