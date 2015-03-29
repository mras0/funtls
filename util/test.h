#include <sstream>
#include <string>

namespace funtls { namespace test {

void assert_failed(const char* file, int line, const std::string& message);

} } // namespace funtls::test

#define FUNTLS_ASSERT_THROWS_MESSAGE(expr, exception_type, message)     \
    do {                                                                \
        try {                                                           \
            expr;                                                       \
            std::ostringstream oss;                                     \
            oss << "Expected " << #expr                                 \
                << " to throw exception of type "                       \
                << #exception_type                                      \
                << "\n" << message;                                     \
            funtls::test::assert_failed(__FILE__,                       \
                    __LINE__, oss.str());                               \
        } catch (const exception_type &) {}                             \
    } while(0)

#define FUNTLS_ASSERT_THROWS(expr, exception_type) \
    FUNTLS_ASSERT_THROWS_MESSAGE(expr, exception_type, "")

#define FUNTLS_ASSERT_BINARY_MESSAGE(bin_op, expected, actual, message) \
    do {                                                                \
        const auto a = (expected);                                      \
        const auto b = (actual);                                        \
        if (!(a bin_op b)) {                                            \
            std::ostringstream oss;                                     \
            oss << "Expected:\n" << #expected << " "                    \
                << #bin_op << " " << #actual << "\n"                    \
                << "Expecetd value:\n" << expected                      \
                << "\nActual:\n" << actual                              \
                << "\n" << message;                                     \
            funtls::test::assert_failed(__FILE__,                       \
                    __LINE__, oss.str());                               \
        }                                                               \
    } while (0)

#define FUNTLS_ASSERT_EQUAL(expected, actual) FUNTLS_ASSERT_BINARY_MESSAGE(==, expected, actual, "")
#define FUNTLS_ASSERT_EQUAL_MESSAGE(message, expected, actual) FUNTLS_ASSERT_BINARY_MESSAGE(==, expected, actual, message)
