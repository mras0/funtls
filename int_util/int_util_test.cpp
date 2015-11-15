#include "int_util.h"
#include "int.h"
#include <util/test.h>
#include <iostream>
#include <boost/math/distributions/chi_squared.hpp>

using namespace funtls;

void test_gcd()
{
    FUNTLS_ASSERT_EQUAL(1, gcd(2, 3));
    FUNTLS_ASSERT_EQUAL(2, gcd(4, 6));
    FUNTLS_ASSERT_EQUAL(6, gcd(54, 24));
    FUNTLS_ASSERT_EQUAL(89, gcd(0, 89));
    FUNTLS_ASSERT_EQUAL(14, gcd(42, 56));

    FUNTLS_ASSERT_EQUAL(large_uint{14}, gcd(large_uint{42}, large_uint{56}));
}

void test_random_large_uint()
{
    for (int i = 0; i < 100; ++i) {
        FUNTLS_ASSERT_BINARY_MESSAGE(rand_int_less(0x100), <, 0x100, "Invalid random number generated");
        FUNTLS_ASSERT_BINARY_MESSAGE(rand_int_less(0x101), <, 0x101, "Invalid random number generated");
        FUNTLS_ASSERT_BINARY_MESSAGE(rand_int_less(0x200), <, 0x200, "Invalid random number generated");
        FUNTLS_ASSERT_BINARY_MESSAGE(rand_int_less(0x401), <, 0x401, "Invalid random number generated");


        const auto pl10 = rand_positive_int_less(0x10);
        FUNTLS_ASSERT_BINARY_MESSAGE(pl10, >, 0x00, "Invalid random number generated");
        FUNTLS_ASSERT_BINARY_MESSAGE(pl10, <, 0x10, "Invalid random number generated");

        const auto plFF = rand_positive_int_less(0xFF);
        FUNTLS_ASSERT_BINARY_MESSAGE(plFF, >, 0x00, "Invalid random number generated");
        FUNTLS_ASSERT_BINARY_MESSAGE(plFF, <, 0xFF, "Invalid random number generated");

        const auto plABCD = rand_positive_int_less(0xABCD);
        FUNTLS_ASSERT_BINARY_MESSAGE(plABCD, >, 0x0000, "Invalid random number generated");
        FUNTLS_ASSERT_BINARY_MESSAGE(plABCD, <, 0xABCD, "Invalid random number generated");

        auto n = rand_positive_int_in_interval<large_uint>(500, 2000);
        FUNTLS_ASSERT_BINARY_MESSAGE(n, >=, 500, "Invalid random number generated");
        FUNTLS_ASSERT_BINARY_MESSAGE(n, <, 2000, "Invalid random number generated");
    }

    //
    // Test the distribution
    //

    constexpr int n_max = 0x382;
    constexpr int test_count = n_max*200;
    std::vector<int> dist(n_max);
    double mean = 0.0;
    for (int i = 0; i < test_count; ++i) {
        const auto t = static_cast<int>(rand_int_less(n_max));
        dist[t]++;
        mean += static_cast<double>(t) / test_count;
    }
    const auto expected_mean = n_max / 2.0;
    FUNTLS_ASSERT_BINARY_MESSAGE(abs(mean - expected_mean)/static_cast<double>(expected_mean), <=, 0.01, "Invalid distribution");

    // Calculate chi-squared
    double chi_squared = 0.0;
    double e_i = static_cast<double>(test_count) / n_max;
    for (int i = 0; i < n_max; ++i) {
        const double t = dist[i] - e_i;
        chi_squared += (t*t)/e_i;
    }
    // Calculate the probability of gettering a results this extreme
    const auto p = 1 - boost::math::cdf(boost::math::chi_squared(n_max), chi_squared);
    FUNTLS_ASSERT_BINARY_MESSAGE(p, >, 1e-5, "Chi-square test failed");
}

void test_random_prime()
{
    const int pmin = 2;
    const int pmax = 32768;
    for (int i = 0; i < 1000; ++i) {
        const int p = static_cast<int>(random_prime<large_uint>(pmin, pmax));
        FUNTLS_ASSERT_BINARY_MESSAGE(p, >=, pmin, "Invalid random prime generated");
        FUNTLS_ASSERT_BINARY_MESSAGE(p, <,  pmax, "Invalid random prime generated");
        if (p == 2) continue;
        FUNTLS_ASSERT_BINARY_MESSAGE(p % 2, !=, 0, "Even 'prime' generated");
        for (int f = 3; f * f <= p; f += 2) {
            FUNTLS_ASSERT_BINARY_MESSAGE(p % f, !=, 0, std::to_string(p) + "%" + std::to_string(f) + " != 0 --> p isn't prime!");
        }
    }
}

int main()
{
    // TODO: More tests
    test_gcd();
    test_random_large_uint();
    test_random_prime();
}
