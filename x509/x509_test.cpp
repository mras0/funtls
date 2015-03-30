#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cassert>
#include <iomanip>
#include <array>

#include <util/base_conversion.h>
#include <util/buffer.h>
#include <asn1/asn1.h>

#include <x509/x509.h>

#include <util/test.h>
#include <hash/sha.h>

#include <boost/multiprecision/cpp_int.hpp>
using int_type = boost::multiprecision::cpp_int;

using namespace funtls;

// TODO: Move to RSA specific file
struct rsa_public_key {
    asn1::integer modolus;           // n
    asn1::integer public_exponent;   // e
};

rsa_public_key rsa_public_key_from_bs(const std::vector<uint8_t>& bs)
{
    funtls::util::buffer_view pk_buf{&bs[0], bs.size()};
    auto elem_seq = funtls::asn1::sequence_view{funtls::asn1::read_der_encoded_value(pk_buf)};
    const auto modolus         = funtls::asn1::integer(elem_seq.next());
    const auto public_exponent = funtls::asn1::integer(elem_seq.next());
    assert(!elem_seq.has_next());
    return rsa_public_key{modolus, public_exponent};
}

std::array<uint8_t, SHA256HashSize> sha256(const void* data, size_t len)
{
    SHA256Context context;
    SHA256Reset(&context);
    SHA256Input(&context, static_cast<const uint8_t*>(data), len);
    std::array<uint8_t, SHA256HashSize> digest;
    SHA256Result(&context, &digest[0]);
    return digest;
}

int_type octets_to_int(const std::vector<uint8_t>& bs)
{
    int_type res = 0;
    for (const auto& elem : bs) {
        res <<= 8;
        res |= elem;
    }
    return res;
}

std::vector<uint8_t> int_to_octets(int_type i, size_t byte_count)
{
    std::vector<uint8_t> result(byte_count);
    while (byte_count--) {
        result[byte_count] = static_cast<uint8_t>(i);
        i >>= 8;
    }
    if (i) {
        throw std::logic_error("Number too large in " + std::string(__PRETTY_FUNCTION__));
    }
    return result;
}

void parse_and_check_x509_v3(util::buffer_view& buf) // in ASN.1 DER encoding (X.690)
{
    auto cert = x509::v3_certificate::parse(asn1::read_der_encoded_value(buf));

    auto c = cert.certificate();
    std::cout << "Certificate:" << std::endl;
    std::cout << " Serial number: 0x" << std::hex << c.serial_number.as<int_type>() << std::dec << std::endl;
    std::cout << " Signature algorithm: " << c.signature_algorithm <<  std::endl;
    std::cout << " Issuer: " << c.issuer << std::endl;
    std::cout << " Validity: Between " << c.validity_not_before << " and " << c.validity_not_after << std::endl;
    std::cout << " Subject: " << c.subject << std::endl;
    assert(c.signature_algorithm == x509::sha256WithRSAEncryption);
    assert(c.subject_public_key_algo == x509::rsaEncryption);

    auto s_pk = rsa_public_key_from_bs(c.subject_public_key.as_vector());
    std::cout << " Subject public key: n=0x" << std::hex << s_pk.modolus.as<int_type>()
        << " e=0x" << s_pk.public_exponent.as<int_type>() << std::dec << std::endl;

    std::cout << "Signature algorithm: " << cert.signature_algorithm() << std::endl;
    assert(cert.signature_algorithm() == x509::sha256WithRSAEncryption);
    auto sig_value = cert.signature().as_vector();
    std::cout << " " << sig_value.size() << " bits" << std::endl;
    std::cout << " " << util::base16_encode(sig_value) << std::endl;

    // The signatureValue field contains a digital signature computed upon
    // the ASN.1 DER encoded tbsCertificate.  The ASN.1 DER encoded
    // tbsCertificate is used as the input to the signature function.

    // See 9.2 EMSA-PKCS1-v1_5 in RFC3447

    // The encrypted signature is stored as a base-256 encoded number in the bitstring
    const auto sig_int  = octets_to_int(sig_value);
    const size_t em_len = sig_value.size(); // encrypted message length

    // Decode the signature using the issuers public key (here using the subjects PK since the cert is selfsigned)
    const auto issuer_pk = s_pk;
    const auto decoded = int_to_octets(powm(sig_int, issuer_pk.public_exponent.as<int_type>(), issuer_pk.modolus.as<int_type>()), em_len);
    std::cout << "Decoded signature:\n" << util::base16_encode(&decoded[0], decoded.size()) << std::endl;

    // EM = 0x00 || 0x01 || PS || 0x00 || T (T=DER encoded DigestInfo)
    auto digest_buf = util::buffer_view{&decoded[0], decoded.size()};
    const auto sig0 = digest_buf.get();
    const auto sig1 = digest_buf.get();
    if (sig0 != 0x00 || sig1 != 0x01) {
        throw std::runtime_error("Invalid PKCS#1 1.5 signature. Expected 0x00 0x01 Got: 0x" + util::base16_encode(&sig0, 1) + " 0x" + util::base16_encode(&sig1, 1));
    }
    // Skip padding
    for (;;) {
        const auto b = digest_buf.get();
        if (b == 0xff) { // Padding...
            continue;
        } else if (b == 0x00) { // End of padding
            break;
        } else {
            throw std::runtime_error("Invalid byte in PKCS#1 1.5 padding: 0x" + util::base16_encode(&b, 1));
        }
    }
    // DigestInfo ::= SEQUENCE {
    //   digestAlgorithm AlgorithmIdentifier,
    //   digest OCTET STRING }

    auto digest_info = asn1::sequence_view{asn1::read_der_encoded_value(digest_buf)};
    assert(digest_buf.remaining() == 0);

    auto digest_algo = x509::read_algorithm_identifer(digest_info.next());
    std::cout << "Digest algorithm: " << digest_algo << std::endl;
    static const asn1::object_id id_sha256{2,16,840,1,101,3,4,2,1};
    assert(digest_algo == id_sha256);
    auto digest = asn1::octet_string{digest_info.next()}.as_vector();
    assert(!digest_info.has_next());

    if (digest.size() != SHA256HashSize) {
        throw std::runtime_error("Invalid digest size expected " + std::to_string(SHA256HashSize) + " got " + std::to_string(digest.size()) + " in " + __PRETTY_FUNCTION__);
    }

    std::cout << "Digest: " << util::base16_encode(&digest[0], digest.size()) << std::endl;

    const auto& cert_buf = cert.certificate_der_encoded();
    const auto calced_digest = sha256(&cert_buf[0], cert_buf.size());
    std::cout << "Calculated digest: " << util::base16_encode(&calced_digest[0], calced_digest.size()) << std::endl;
    if (!std::equal(calced_digest.begin(), calced_digest.end(), digest.begin())) {
        throw std::runtime_error("Digest mismatch in " + std::string(__PRETTY_FUNCTION__) + " Calculated: " +
                util::base16_encode(&calced_digest[0], calced_digest.size()) + " Expected: " +
                util::base16_encode(&digest[0], digest.size()));
    }
}

std::vector<uint8_t> read_file(const std::string& filename)
{
    std::ifstream in(filename);
    if (!in || !in.is_open()) {
        throw std::runtime_error("Could not open " + filename);
    }
    in.seekg(0, std::ifstream::end);
    std::vector<uint8_t> buffer(in.tellg());
    in.seekg(0, std::ifstream::beg);
    in.read(reinterpret_cast<char*>(&buffer[0]), buffer.size());
    if (!in) {
        throw std::runtime_error("Error reading from " + filename);
    }
    return buffer;
}

int main()
{
    auto cert = read_file("server.crt");
    assert(cert.size());
    util::buffer_view cert_buf(&cert[0], cert.size());
    parse_and_check_x509_v3(cert_buf);
}
