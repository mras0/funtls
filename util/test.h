#include <sstream>
#include <string>
#include <cstdlib>

namespace funtls { namespace test {

void check_failed(const char* func, const char* file, int line, const std::string& message);
void assert_failed(const char* func, const char* file, int line, const std::string& message);

} } // namespace funtls::test

#define FUNTLS_CHECK_FAILURE(msg) do {                                  \
    funtls::test::check_failed(__PRETTY_FUNCTION__, __FILE__,           \
                    __LINE__, msg);                                     \
    std::abort();                                                       \
    } while (0)

#define FUNTLS_ASSERT_THROWS_MESSAGE(expr, exception_type, message)     \
    do {                                                                \
        try {                                                           \
            expr;                                                       \
            std::ostringstream oss;                                     \
            oss << "Expected " << #expr                                 \
                << " to throw exception of type "                       \
                << #exception_type                                      \
                << "\n" << message;                                     \
            funtls::test::assert_failed(__PRETTY_FUNCTION__, __FILE__,  \
                    __LINE__, oss.str());                               \
        } catch (const exception_type &) {}                             \
    } while(0)

#define FUNTLS_ASSERT_THROWS(expr, exception_type) \
    FUNTLS_ASSERT_THROWS_MESSAGE(expr, exception_type, "")

#define FUNTLS_CHECK_BINARY_(bin_op, expected, actual, message, fail)   \
    do {                                                                \
        const auto a = (expected);                                      \
        const auto b = (actual);                                        \
        if (!(a bin_op b)) {                                            \
            std::ostringstream oss;                                     \
            oss << "Expected:\n" << #expected << " "                    \
                << #bin_op << " " << #actual << "\n"                    \
                << "Failure:\n"                                         \
                << a << " " << #bin_op << " " << b << "\n" << message;  \
            fail(__PRETTY_FUNCTION__, __FILE__,                         \
                    __LINE__, oss.str());                               \
        }                                                               \
    } while (0)

#define FUNTLS_ASSERT_BINARY_MESSAGE(bin_op, expected, actual, message) \
    FUNTLS_CHECK_BINARY_(bin_op, expected, actual, message, funtls::test::assert_failed)

#define FUNTLS_ASSERT_EQUAL(expected, actual) FUNTLS_ASSERT_BINARY_MESSAGE(==, expected, actual, "")
#define FUNTLS_ASSERT_EQUAL_MESSAGE(message, expected, actual) FUNTLS_ASSERT_BINARY_MESSAGE(==, expected, actual, message)

#define FUNTLS_CHECK_BINARY(expected, bin_op, actual, message) \
    FUNTLS_CHECK_BINARY_(bin_op, expected, actual, message, funtls::test::check_failed)
