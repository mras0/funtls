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
    virtual sign_result_t do_sign(const std::vector<uint8_t>&) const override {
        std::vector<uint8_t> sig;
        return std::make_pair(x509::algorithm_id{x509::id_sha256WithRSAEncryption}, sig);
    }
};


#include <int_util/int.h>
#include <int_util/int_util.h>

asn1::integer to_asn1_int(large_uint n, unsigned byte_count) {
    return asn1::integer::from_bytes(be_uint_to_bytes(n, byte_count));
}

x509::rsa_private_key make_rsa_private_key()
{
    constexpr unsigned byte_count = 2048 / 8;

    // 1. Choose two distinct prime numbers p and q.
    const large_uint p = 61;
    const large_uint q = 53;
    std::cout << "p = " << p << std::endl;
    std::cout << "q = " << q << std::endl;
    // 2. Compute n = pq.
    const large_uint n = p * q;
    std::cout << "n = " << n << std::endl;
    // 3. Compute phi(n) = phi(p)phi(q) =  (p ? 1)(q ? 1) = n - (p + q - 1)
    const large_uint phi_n = n - (p + q - 1);
    std::cout << "phi(n) = " << phi_n << std::endl;
    // 4. Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
    const large_uint e = 17;
    //assert(gcd(phi_n, e) == 1);
    // 5. Determine d as d == e^?1 (mod phi(n)); i.e., d is the multiplicative inverse of e (modulo phi(n)).
    const large_uint d = modular_inverse(e, phi_n);
    assert(large_uint((e*d) % phi_n) == 1);

    std::cout << "Public key: (" << n << ", " << e << ")\n";
    std::cout << "Private key: " << d << std::endl;
    return x509::rsa_private_key{
        asn1::integer{0},                                   // version          = two-prime
        to_asn1_int(n, byte_count),                         // modulus          = n
        to_asn1_int(e, byte_count),                         // public_exponent  = e
        to_asn1_int(d, byte_count),                         // private_exponent = d
        to_asn1_int(p, byte_count),                         // prime1           = p
        to_asn1_int(q, byte_count),                         // prime2           = q
        to_asn1_int(d % (p - 1), byte_count),               // exponent1        = d mod (p-1)
        to_asn1_int(d % (q - 1), byte_count),               // exponent2        = d mod (q-1)
        to_asn1_int(modular_inverse(q, p), byte_count)};    // coefficient      = (inverse of q) mod p
}

void make()
{
    const auto private_key = make_rsa_private_key();

    x509::write_pem_private_key_info(std::cout, make_private_key_info(private_key));
    std::cout  << "\n\n";

    x509::name subject{{std::make_pair(x509::attr_commonName, asn1::ia5_string{"localhost"})}};
    
    const asn1::utc_time not_before{"1511080000Z"};
    const asn1::utc_time not_after{"2511080000Z"};
    const asn1::bit_string subject_public_key_bs{asn1::serialized(x509::rsa_public_key::from_private(private_key))};

    x509::tbs_certificate tbs{
        x509::version::v3,                                    // version
        asn1::integer::from_bytes({0x01}),                    // serial_number
        x509::algorithm_id{x509::id_sha256WithRSAEncryption}, // signature_algorithm
        subject,                                              // issuer
        not_before,                                           // validity_not_before
        not_after,                                            // validity_not_after
        subject,                                              // subect
        x509::algorithm_id{x509::id_rsaEncryption},           // subject_public_key_algo
        subject_public_key_bs,                                // subject_public_key
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
