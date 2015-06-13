#include "async_result.h"
#include "base_conversion.h"
#include "buffer.h"
#include "test.h"
#include <stdexcept>
#include <memory>

template<typename T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& vec)
{
    os << "{";
    for (const auto& x : vec) {
        os << " " << x;
    }
    os << " }";
    return os;
}

void base16_test()
{
    static const struct {
        const char* base16;
        std::vector<uint8_t> bytes;
    } vector_test_cases[] = {
        {"", {}},
        {"00", {0x00}},
        {"00FE", {0,0xfe}},
        {"1234", {0x12,0x34}},
        {"0123456789ABCDEF", {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}},
        // Test vectors from https://tools.ietf.org/html/rfc4648 section 10
        {"66", {'f'}},
        {"666F", {'f','o'}},
        {"666F6F", {'f','o','o'}},
        {"666F6F62", {'f','o','o','b'}},
        {"666F6F6261", {'f','o','o','b','a'}},
        {"666F6F626172", {'f','o','o','b','a','r'}},
    };

    using namespace funtls::util;
    for (const auto& test_case : vector_test_cases) {
        FUNTLS_ASSERT_EQUAL(test_case.base16, base16_encode(test_case.bytes));
        FUNTLS_ASSERT_EQUAL(test_case.bytes, base16_decode(test_case.base16));
    }

    uint8_t arr[] = { 0xaa, 0x55 };
    FUNTLS_ASSERT_EQUAL("", base16_encode(arr, 0));
    FUNTLS_ASSERT_EQUAL("AA", base16_encode(arr, 1));
    FUNTLS_ASSERT_EQUAL("AA55", base16_encode(arr, sizeof(arr)));

    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{}), base16_decode("AA55", 0));
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0xaa}), base16_decode("Aa55", 2));
    FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{0xaa,0x55}), base16_decode("aa55", 4));

    FUNTLS_ASSERT_THROWS(base16_decode("aa", 1), std::runtime_error);
    FUNTLS_ASSERT_THROWS(base16_decode("ga", 2), std::runtime_error);
    FUNTLS_ASSERT_THROWS(base16_decode("ag", 2), std::runtime_error);
    FUNTLS_ASSERT_THROWS(base16_decode("xy", 2), std::runtime_error);
}

std::string vec2str(const std::vector<uint8_t>& vec)
{
    if (vec.empty()) return "";
    return std::string(reinterpret_cast<const char*>(&vec[0]), vec.size());
}

std::vector<uint8_t> str2vec(const std::string& s)
{
    if (s.empty()) return {};
    auto data = reinterpret_cast<const uint8_t*>(s.data());
    return std::vector<uint8_t>(data, data+s.length());
}

#include <iostream>

void base64_test()
{
    static const struct {
        const std::string plain;
        const std::string base64;
    } base64_test_cases[] = {
        // Test vectors from https://tools.ietf.org/html/rfc4648 section 10
        { "", "" },
        { "f", "Zg==" },
        { "fo", "Zm8=" },
        { "foo", "Zm9v" },
        { "foob", "Zm9vYg==" },
        { "fooba", "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },

        // TODO: Test non printable characters
    };

    using namespace funtls::util;
    for (const auto& test_case : base64_test_cases) {
        FUNTLS_ASSERT_EQUAL_MESSAGE(test_case.plain, vec2str(base64_decode(test_case.base64)), test_case.base64);
        FUNTLS_ASSERT_EQUAL_MESSAGE(test_case.base64, base64_encode(str2vec(test_case.plain)), test_case.plain);
        // TODO:test non-vector/non-string versions
    }
    // TODO: Test throws
}

void buffer_test()
{
    const uint8_t source[] = { 0, 1, 2, 3, 4, 5 };

    using namespace funtls::util;

    buffer_view buf{source, sizeof(source)};
    FUNTLS_ASSERT_EQUAL(6, buf.size());
    FUNTLS_ASSERT_EQUAL(6, buf.remaining());
    FUNTLS_ASSERT_EQUAL(0, buf.index());

    buffer_view cpy = buf;
    FUNTLS_ASSERT_EQUAL(6, cpy.size());
    FUNTLS_ASSERT_EQUAL(6, cpy.remaining());
    FUNTLS_ASSERT_EQUAL(0, cpy.index());

    FUNTLS_ASSERT_EQUAL(0, cpy.get());
    FUNTLS_ASSERT_EQUAL(5, cpy.remaining());
    FUNTLS_ASSERT_EQUAL(1, cpy.index());
    FUNTLS_ASSERT_EQUAL(6, cpy.size());
    FUNTLS_ASSERT_EQUAL(6, buf.remaining()); // We didn't consume any bytes from the source

    auto copy_of_copy = cpy;
    FUNTLS_ASSERT_EQUAL(5, copy_of_copy.remaining());
    FUNTLS_ASSERT_EQUAL(6, copy_of_copy.size());
    FUNTLS_ASSERT_EQUAL(1, cpy.index());

    FUNTLS_ASSERT_EQUAL(1, cpy.get());
    FUNTLS_ASSERT_EQUAL(2, cpy.get());
    FUNTLS_ASSERT_EQUAL(3, cpy.get());
    FUNTLS_ASSERT_EQUAL(4, cpy.get());
    FUNTLS_ASSERT_EQUAL(5, cpy.get());
    FUNTLS_ASSERT_EQUAL(0, cpy.remaining());
    FUNTLS_ASSERT_EQUAL(6, cpy.index());
    FUNTLS_ASSERT_EQUAL(6, cpy.size());
    FUNTLS_ASSERT_THROWS(cpy.get(), std::runtime_error);

    auto slice = buf.get_slice(3);
    FUNTLS_ASSERT_EQUAL(3, slice.size());
    FUNTLS_ASSERT_EQUAL(3, slice.remaining());
    FUNTLS_ASSERT_EQUAL(3, buf.remaining());
    FUNTLS_ASSERT_EQUAL(6, buf.size());
    FUNTLS_ASSERT_EQUAL(3, buf.get());
    uint8_t dest[2];
    buf.read(dest, sizeof(dest));
    FUNTLS_ASSERT_EQUAL(4, dest[0]);
    FUNTLS_ASSERT_EQUAL(5, dest[1]);
    FUNTLS_ASSERT_THROWS(buf.read(dest, sizeof(dest)), std::runtime_error);

    buffer_view empty{source, 0};
    FUNTLS_ASSERT_EQUAL(0, empty.size());
    FUNTLS_ASSERT_EQUAL(0, empty.remaining());
    FUNTLS_ASSERT_THROWS(empty.get(), std::runtime_error);
}

void test_buffer_getters()
{
    using namespace funtls::util;
    const uint8_t buffer[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    { buffer_view buf{buffer, sizeof(buffer)}; FUNTLS_ASSERT_EQUAL(0x01, get_be_uint8(buf)); }
    { buffer_view buf{buffer, sizeof(buffer)}; FUNTLS_ASSERT_EQUAL(0x0123, get_be_uint16(buf)); }
    { buffer_view buf{buffer, sizeof(buffer)}; FUNTLS_ASSERT_EQUAL(0x01234567, get_be_uint32(buf)); }
    { buffer_view buf{buffer, sizeof(buffer)}; FUNTLS_ASSERT_EQUAL(0x0123456789abcdef, get_be_uint64(buf)); }
}

void test_async_result()
{
    using namespace funtls::util;
    {
        async_result<int> res(42);
        FUNTLS_ASSERT_EQUAL(true, static_cast<bool>(res));
        FUNTLS_ASSERT_EQUAL(42, res.get());
        FUNTLS_ASSERT_EQUAL(42, make_async_result<int>(42).get());
    }
    {
        async_result<int> res(std::make_exception_ptr(std::logic_error("Test")));
        FUNTLS_ASSERT_EQUAL(false, static_cast<bool>(res));
        FUNTLS_ASSERT_THROWS(res.get(), std::logic_error);
        FUNTLS_ASSERT_THROWS(std::rethrow_exception(res.get_exception()), std::logic_error);
    }
    {
        async_result<std::vector<uint8_t>> res(std::vector<uint8_t>{1,2,3});
        FUNTLS_ASSERT_EQUAL(true, static_cast<bool>(res));
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{1,2,3}), res.get());
        FUNTLS_ASSERT_EQUAL((std::vector<uint8_t>{1,2,3}), make_async_result(std::vector<uint8_t>{1,2,3}).get());
    }
    {
        async_result<void> res{};
        FUNTLS_ASSERT_EQUAL(true, static_cast<bool>(res));
        res.get();
        make_async_result().get();
    }
    {
        async_result<void> res(std::make_exception_ptr(std::logic_error("Test")));
        FUNTLS_ASSERT_EQUAL(false, static_cast<bool>(res));
        FUNTLS_ASSERT_THROWS(res.get(), std::logic_error);
        FUNTLS_ASSERT_THROWS(std::rethrow_exception(res.get_exception()), std::logic_error);
    }

    // Make sure async_result can be moved and returned
    {
        async_result<int> res(42);
        auto foo = [] (async_result<int>&& r) {
            FUNTLS_ASSERT_EQUAL(42, r.get());
            return make_async_result<int>(60);
        };
        auto r2 = foo(std::move(res));
        FUNTLS_ASSERT_EQUAL(60, r2.get());
    }
    {
        async_result<void> res{};
        auto foo = [] (async_result<void>&& r) {
            r.get();
            return async_result<void>(std::make_exception_ptr(std::logic_error("Test")));
        };
        auto r2 = foo(std::move(res));
        FUNTLS_ASSERT_THROWS(r2.get(), std::logic_error);
    }
    {
        async_result<std::vector<int>> res({8,4,2});
        auto foo = [] (async_result<std::vector<int>>&& r) {
            FUNTLS_ASSERT_EQUAL((std::vector<int>{8,4,2}), r.get());
            return make_async_result<std::vector<int>>({2,3,4});
        };
        auto r2 = foo(std::move(res));
        FUNTLS_ASSERT_EQUAL((std::vector<int>{2,3,4}), r2.get());
    }

    {
        auto r = make_async_result(std::unique_ptr<int>(new int(1337)));
        FUNTLS_ASSERT_EQUAL(1337, *r.get());
    }
}

int main()
{
    base16_test();
    base64_test();
    buffer_test();
    test_buffer_getters();
    test_async_result();
}
