#include "variant.h"

static_assert(tls::detail::get_index<int, int>() == 0, "");
static_assert(tls::detail::get_index<int, double, int>() == 1, "");
static_assert(tls::detail::get_index<int, double, float, int>() == 2, "");

struct A {};
struct B {};
struct C : public A {};

static_assert(tls::detail::get_index<A, A, B, C>() == 0, "");
static_assert(tls::detail::get_index<B, A, B, C>() == 1, "");
static_assert(tls::detail::get_index<C, A, B, C>() == 2, "");

static_assert(tls::detail::max_size<short>::value == 2, "");
static_assert(tls::detail::max_size<double>::value == 8, "");
static_assert(tls::detail::max_size<double,char>::value == 8, "");
static_assert(tls::detail::max_size<short,char,long long>::value == 8, "");
