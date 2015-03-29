#include <sstream>
#include <string>

namespace funtls { namespace test {

void assert_failed(const char* file, int line, const std::string& message);

} } // namespace funtls::test

#define FUNTLS_ASSERT_BINARY(bin_op, expected, actual) \
    do {                                               \
        const auto a = (expected);                     \
        const auto b = (actual);                       \
        if (!(a bin_op b)) {                           \
            std::ostringstream oss;                    \
            oss << "Expected:\n" << #expected << " "   \
                << #bin_op << " " << #actual << "\n"   \
                << "Expecetd value:\n" << expected     \
                << "\nActual:\n" << actual;            \
            funtls::test::assert_failed(__FILE__,      \
                    __LINE__, oss.str());              \
        }                                              \
    } while (0)

#define FUNTLS_ASSERT_EQUAL(expected, actual) FUNTLS_ASSERT_BINARY(==, expected, actual)
