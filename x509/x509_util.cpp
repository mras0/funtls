#include <iostream>
#include <fstream>
#include <string>
#include <util/base_conversion.h>
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

#include <util/test.h>
#include <int_util/int.h>
#include <int_util/int_util.h>

asn1::integer to_asn1_int(large_uint n, unsigned byte_count) {
    auto bytes = be_uint_to_bytes(n, byte_count);
    if (bytes[0] & 0x80) bytes.insert(bytes.begin(), 0x00);
    return asn1::integer::from_bytes(bytes);
}

// openssl rsa -check -inform pem -text -noout
x509::rsa_private_key generate_rsa_private_key(unsigned bit_count)
{
    // 1. Choose two distinct prime numbers p and q.
    const large_uint p = random_prime<large_uint>(large_uint{1}<<((bit_count/2)-1), large_uint{1}<<(bit_count/2));
    assert(p >= large_uint{1}<<(bit_count/2-1) && p < (large_uint{1}<<(bit_count/2)));
    std::cout << "p = " << p << std::endl;
    const large_uint q = random_prime<large_uint>((large_uint{1}<<(bit_count-1))/p + 1, (((large_uint{1}<<bit_count)-1)/p)+1);
    std::cout << "q = " << q << std::endl;
    // 2. Compute n = pq.
    const large_uint n = p * q;
    std::cout << "n = " << n << std::endl;
    assert(n >= large_uint{1}<<(bit_count-1) && n < (large_uint{1}<<bit_count));
    
    // 3. Compute phi(n) = phi(p)phi(q) =  (p ? 1)(q ? 1) = n - (p + q - 1)
    const large_uint phi_n = n - (p + q - 1);
    std::cout << "phi(n) = " << phi_n << std::endl;
    // 4. Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
    large_uint e = 0;
    for (int iter=0;;++iter) {
        FUNTLS_CHECK_BINARY(iter, <, 1000, "Took too many iterations to find public exponent");
        e = rand_positive_int_less(phi_n);
        if (gcd(phi_n, e) == 1) break;
    }
    
    // 5. Determine d as d == e^?1 (mod phi(n)); i.e., d is the multiplicative inverse of e (modulo phi(n)).
    const large_uint d = modular_inverse(e, phi_n);
    assert(large_uint((e*d) % phi_n) == 1);

    std::cout << "Public key: (" << n << ", " << e << ")\n";
    std::cout << "Private key: " << d << std::endl;

    const unsigned byte_count = (bit_count+7) / 8;
    assert(ilog256(n) == byte_count);

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

void make_rsa_private_key(unsigned bit_count)
{
    x509::write_pem_private_key_info(std::cout, make_private_key_info(generate_rsa_private_key(bit_count)));
    std::cout << "\n";
}

#include <hash/hash.h>
class rsa_certificate_signer : public x509::certificate_signer {
public:
    rsa_certificate_signer(const asn1::object_id& digest_algo_id, const x509::rsa_private_key& private_key)
        : digest_algo_id_(digest_algo_id)
        , private_key_(private_key) {
    }

private:
    asn1::object_id              digest_algo_id_;
    const x509::rsa_private_key& private_key_;

    virtual sign_result_t do_sign(const std::vector<uint8_t>& certificate_der_encoded) const override {
        assert(digest_algo_id_ == x509::id_sha1);
        x509::digest_info di{x509::algorithm_id{digest_algo_id_}, hash::sha1{}.input(certificate_der_encoded).result()};
        return std::make_pair(x509::algorithm_id{x509::id_sha1WithRSAEncryption}, x509::pkcs1_encode(private_key_, asn1::serialized(di)));
    }
};

void make_certificate()
{
    const auto private_key = generate_rsa_private_key(1024);

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
    const x509::algorithm_id algo_id{x509::id_sha1WithRSAEncryption};

    x509::tbs_certificate tbs{
        x509::version::v3,                                    // version
        asn1::integer::from_bytes({0x01}),                    // serial_number
        algo_id,                                              // signature_algorithm
        subject,                                              // issuer
        not_before,                                           // validity_not_before
        not_after,                                            // validity_not_after
        subject,                                              // subect
        x509::algorithm_id{x509::id_rsaEncryption},           // subject_public_key_algo
        subject_public_key_bs,                                // subject_public_key
        {}                                                    // extensions
    };

    auto cert = rsa_certificate_signer{x509::id_sha1, private_key}.sign(tbs);
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
