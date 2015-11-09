#include "int_util.h"
#include "int.h"
#include <util/test.h>
#include <iostream>

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

int main()
{
    // TODO: More tests
    test_gcd();
}
