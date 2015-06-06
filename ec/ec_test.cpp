#include <ec/ec.h>
#include <util/base_conversion.h>
#include <util/test.h>
#include <util/int_util.h>

#include <iostream>

using namespace funtls;

ec::curve make_curve(const ec::field_elem& p, const ec::field_elem& a, const ec::field_elem& b) {
    return {
        p, a, b,
        ec::infinity, // G
        0, // n
        1, // h
    };
}

int main()
{
    {
        const auto C = make_curve(5, 1, 1);
        const auto P = ec::point{2, 1};
        FUNTLS_ASSERT_EQUAL(true, C.on_curve(P));
        FUNTLS_ASSERT_EQUAL((ec::point{2,4}), C.add(P,P));
        FUNTLS_ASSERT_EQUAL(ec::infinity, C.add(C.add(P,P),P));
    }
    {
        const auto curve_p = 2147483647;
        const auto min_2 = curve_p-2;
        const auto C = make_curve(curve_p, min_2, 4);
        const auto P = ec::point{3, 5};
        const auto Q = ec::point{min_2, 0};
        FUNTLS_ASSERT_EQUAL(true, C.on_curve(P));
        FUNTLS_ASSERT_EQUAL(true, C.on_curve(Q));
        FUNTLS_ASSERT_EQUAL((ec::point{0,min_2}), C.add(P,Q));
        FUNTLS_ASSERT_EQUAL((ec::point{0,min_2}), C.add(Q, P));
        FUNTLS_ASSERT_EQUAL(ec::infinity, C.add(Q, Q));
    }
}
