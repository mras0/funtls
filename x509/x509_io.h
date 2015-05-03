#include <iosfwd>
#include <string>
#include <vector>

#include "x509.h"

namespace funtls { namespace x509 {

v3_certificate read_pem_certificate(std::istream& is);
v3_certificate read_pem_certificate(const std::string& s);

void write_pem_certificate(std::ostream& os, const std::vector<uint8_t>& der_encoded_certificate);

} } // namespace funtls::x509
