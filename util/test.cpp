#include "test.h"
#include <iostream>
#include <cstdlib>

namespace funtls { namespace test {

void assert_failed(const char* file, int line, const std::string& message)
{
    std::cerr << "Assertion failed in " << file << " line " << line << std::endl;
    std::cerr << message << std::endl;
    std::abort();
}

} } // namespace funtls::test
