#include <iosfwd>
#include <string>
#include <vector>

#include "x509.h"

namespace funtls { namespace x509 {

certificate read_pem_certificate(std::istream& is);
certificate read_pem_certificate_from_string(const std::string& s);
certificate read_pem_certificate_from_file(const std::string& filename);

void write_pem_certificate(std::ostream& os, const std::vector<uint8_t>& der_encoded_certificate);
void write_pem_private_key_info(std::ostream& os, const private_key_info& pki);

private_key_info read_pem_private_key(std::istream& is);
private_key_info read_pem_private_key_from_string(const std::string& s);
private_key_info read_pem_private_key_from_file(const std::string& filename);

} } // namespace funtls::x509
