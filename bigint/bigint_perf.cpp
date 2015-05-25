#include <iostream>
#include <chrono>
#include <string>
#include <util/test.h>
#include <util/int_util.h>

template<typename Clock>
uint64_t clock_ns()
{
    const auto now_ticks = Clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now_ticks).count();
}

template<typename F>
double time_it(const F& f)
{
    auto ns = clock_ns<std::chrono::high_resolution_clock>;
    const auto start_time = ns();
    f();
    const auto end_time = ns();
    return (end_time - start_time) / 1e9;
}

uint32_t rand_state = 0x123456;

template<typename I>
I rand_int(size_t num_bytes=1024/8)
{
    std::vector<uint8_t> bytes(num_bytes);
    for (auto& b : bytes) {
        rand_state = rand_state * 22695477 + 1;
        b = rand_state & 0xff;
    }
    return funtls::be_uint_from_bytes<I>(bytes);
}

template<typename I> bool always_accept(const I&, const I&){ return true; }

template<typename I, typename Calc, typename Check, typename Accept>
void time_bin_op(const std::string& name, Calc calc, Check check, Accept accept)
{
    int times = 10;
    double time_sum = 0;
    for (int i = 0; i < times;) {
        const I a = rand_int<I>();
        const I b = rand_int<I>();
        if (!accept(a, b)) continue;
        ++i;
        I r;
        time_sum += time_it([&] { calc(r, a, b); });
        check(r, a, b);
    }
    const auto avg = time_sum / times;
    std::cout << name << " avg " << avg*1e6 << " ms" << std::endl;
}

template<typename I> void test_add(I& r, const I& a, const I& b) { r = a + b; }
template<typename I> void check_add(const I& r, const I& a, const I& b) { FUNTLS_CHECK_BINARY(I(r - a), ==, b, ""); }
template<typename I> void test_sub(I& r, const I& a, const I& b) { r = a - b; }
template<typename I> void check_sub(const I& r, const I& a, const I& b) { FUNTLS_CHECK_BINARY(I(r + b), ==, a, ""); }
template<typename I> void test_mul(I& r, const I& a, const I& b) { r = a * b; }
template<typename I> void check_mul(const I& r, const I& a, const I& b) { FUNTLS_CHECK_BINARY(I(r - a * b), ==, 0, ""); }
template<typename I> void test_div(I& r, const I& a, const I& b) { r = a / b; }
template<typename I> void check_div(const I& r, const I& a, const I& b) { FUNTLS_CHECK_BINARY(I(r * b + a % b), ==, a, ""); }
template<typename I> void test_mod(I& r, const I& a, const I& b) { r = a % b; }
template<typename I> void check_mod(const I& r, const I& a, const I& b) { FUNTLS_CHECK_BINARY(I(b*(a/b)+r), ==, a, ""); }

template<typename I>
void test(const std::string& name)
{
    time_bin_op<I>(name + " add", &test_add<I>, &check_add<I>, &always_accept<I>);
    time_bin_op<I>(name + " sub", &test_sub<I>, &check_sub<I>, [](const I& a, const I& b){return a >= b;});
    time_bin_op<I>(name + " mul", &test_mul<I>, &check_mul<I>, &always_accept<I>);
    time_bin_op<I>(name + " div", &test_div<I>, &check_div<I>, [](const I&, const I& b){return b != 0;});
    time_bin_op<I>(name + " mod", &test_mod<I>, &check_mod<I>, [](const I&, const I& b){return b != 0;});
}

#include <bigint/bigint.h>
#include <boost/multiprecision/cpp_int.hpp>
int main()
{
#define T(c) test<c>(#c);
    T(boost::multiprecision::cpp_int);
    T(funtls::bigint::biguint);
#undef T
}
