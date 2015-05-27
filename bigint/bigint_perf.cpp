#include <iostream>
#include <chrono>
#include <string>
#include <vector>
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

template<typename Derived, typename I>
struct bin_op_test_base {
    static std::vector<double> time()
    {
        const int times = 10;
        std::vector<double> results;
        for (int i = 0; i < times;) {
            const I a = rand_int();
            const I b = rand_int();
            if (!Derived::accept(a, b)) continue;
            ++i;
            I r;
            const double trial = time_it([&] { Derived::calc(r, a, b); });
            results.push_back(trial);
            Derived::check(r, a, b);
        }

        return results;
    }

    static bool accept(const I&, const I&) {
        return true;
    }

    static I rand_int(size_t num_bytes=1024/8)
    {
        std::vector<uint8_t> bytes(num_bytes);
        static uint32_t rand_state = 0x123456;
        for (auto& b : bytes) {
            rand_state = rand_state * 22695477 + 1;
            b = rand_state & 0xff;
        }
        return funtls::be_uint_from_bytes<I>(bytes);
    }
};

template<typename I>
struct add_test : bin_op_test_base<add_test<I>, I> {
    static void calc(I& r, const I& a, const I& b) {
        r = a + b;
    }
    static void check(const I& r, const I& a, const I& b) {
        FUNTLS_CHECK_BINARY(I(r - a), ==, b, "");
    }
};

template<typename I>
struct sub_test : bin_op_test_base<sub_test<I>, I> {
    static bool accept(const I& a, const I& b) {
        return a >= b;
    }
    static void calc(I& r, const I& a, const I& b) {
        r = a - b;
    }
    static void check(const I& r, const I& a, const I& b) {
        FUNTLS_CHECK_BINARY(I(r + b), ==, a, "");
    }
};

template<typename I>
struct mul_test : bin_op_test_base<mul_test<I>, I> {
    static void calc(I& r, const I& a, const I& b) {
        r = a * b;
    }
    static void check(const I& r, const I& a, const I& b) {
        FUNTLS_CHECK_BINARY(I(r - a * b), ==, 0, "");
    }
};

template<typename I>
struct div_test : bin_op_test_base<div_test<I>, I> {
    static bool accept(const I&, const I& b) {
        return b != 0;
    }
    static void calc(I& r, const I& a, const I& b) {
        r = a / b;
    }
    static void check(const I& r, const I& a, const I& b) {
        FUNTLS_CHECK_BINARY(I(r * b + a % b), ==, a, "");
    }
};

template<typename I>
struct mod_test : bin_op_test_base<mod_test<I>, I> {
    static bool accept(const I&, const I& b) {
        return b != 0;
    }
    static void calc(I& r, const I& a, const I& b) {
        r = a % b;
    }
    static void check(const I& r, const I& a, const I& b) {
        FUNTLS_CHECK_BINARY(I(b*(a/b)+r), ==, a, "");
    }
};

using results_t = std::vector<std::pair<std::string, std::vector<double>>>;

template<typename I>
void test(const std::string& name, results_t& res)
{
    res.emplace_back("add " + name, add_test<I>::time());
    res.emplace_back("sub " + name, sub_test<I>::time());
    res.emplace_back("mul " + name, mul_test<I>::time());
    res.emplace_back("div " + name, div_test<I>::time());
    res.emplace_back("mod " + name, mod_test<I>::time());
}

void report(const results_t& results)
{
    constexpr int namew = 20;
    constexpr int resw  = 8;
    std::cout << std::left << std::setw(namew) << "Name";
    static const char* titles[] = {
        "Min",
        "25th",
        "Med",
        "75th",
        "Max",
        "Mean",
        "Sigma",
    };
    std::cout << std::right;
    for (auto t : titles) {
        std::cout << " " << std::setw(resw) << t;
    }
    std::cout << std::left;
    std::cout << std::endl;
    std::cout << std::string(namew + sizeof(titles)/sizeof(*titles) * (resw+1), '-') << std::endl;
    for (const auto& res : results) {
        auto ts = res.second;
        std::sort(ts.begin(), ts.end());
        for (auto& t : ts) t *= 1e9;
        const double total = std::accumulate(ts.begin(), ts.end(), 0.0);
        const double mean = total / ts.size();
        const double sum_deviation2 = std::accumulate(ts.begin(), ts.end(), 0.0,
                [=](double s, double b) { return s + (b-mean)*(b-mean); });
        const double stdandard_deviation = sqrt(sum_deviation2 / ts.size());
        std::cout << std::setw(namew) << res.first;
        std::cout << std::right;
        std::cout << " " << std::setw(resw) << (int64_t)ts[0];
        std::cout << " " << std::setw(resw) << (int64_t)ts[ts.size()/4];
        std::cout << " " << std::setw(resw) << (int64_t)ts[ts.size()/2];
        std::cout << " " << std::setw(resw) << (int64_t)ts[ts.size()*3/4];
        std::cout << " " << std::setw(resw) << (int64_t)ts[ts.size()-1];
        std::cout << " " << std::setw(resw) << mean;
        std::cout << " " << std::setw(resw) << stdandard_deviation;
        std::cout << std::left;
        std::cout << std::endl;
    }
}

#include <bigint/bigint.h>
#include <boost/multiprecision/cpp_int.hpp>
int main()
{
    results_t results;
    test<boost::multiprecision::cpp_int>("boost", results);
    test<funtls::bigint::biguint>("funtls", results);
    std::sort(results.begin(), results.end());
    report(results);
}
