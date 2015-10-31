#include "test.h"
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <stdexcept>

namespace funtls { namespace test {

// TODO: Optionally grab stack trace

void assert_failed(const char* func, const char* file, int line, const std::string& message)
{
    std::cerr << "Assertion failed in " << func << " " << file << " line " << line << std::endl;
    std::cerr << message << std::endl;
    std::abort();
}

void check_failed(const char* func, const char* file, int line, const std::string& message)
{
    std::ostringstream oss;
    oss << "Check failed in " << func << " " << file << " line " << line << std::endl;
    oss << message;
    throw std::runtime_error(oss.str());
}

} } // namespace funtls::test
