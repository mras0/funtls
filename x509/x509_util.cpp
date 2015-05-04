#include <iostream>
#include <fstream>
#include <string>
#include <x509/x509.h>
#include <x509/x509_rsa.h>
#include <x509/x509_io.h>

using namespace funtls;

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <file>\n";
        return 0;
    }

    const std::string filename = argv[1];
    std::ifstream in(filename, std::ifstream::binary);
    if (!in || !in.is_open()) {
        throw std::runtime_error("Error opening " + filename);
    }
    std::cout << filename << std::endl;
    while (in && in.peek() != std::char_traits<char>::eof()) {
        auto cert = x509::read_pem_certificate(in);
        std::cout << cert << std::endl;
        if (cert.tbs().issuer == cert.tbs().subject) {
            std::cout << "Verifying self-signed certificate...";
            try {
                verify_x509_signature(cert, cert);
                std::cout << "OK\n";
            } catch (const std::runtime_error& e) {
                std::cout << e.what() << "\n";
            }
        }
    }
}
