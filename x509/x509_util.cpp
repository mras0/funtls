#include <iostream>
#include <fstream>
#include <string>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <x509/x509_io.h>

using namespace funtls;
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
            const std::string filename = consume_argv();
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
        } else if (command == "make") {
        } else {
            std::cout << "Unknown command '" << command << "'\n";
            usage();
        }
    } catch (const std::runtime_error& e) {
        std::cout << e.what() << "\n";
    }
}
