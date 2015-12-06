#ifndef FUNTLS_SERVER_TEST_UTILS_H_INCLUDED
#define FUNTLS_SERVER_TEST_UTILS_H_INCLUDED

#include <functional>

namespace boost { namespace asio {
class io_service;
} } // namespace boost::asio

namespace funtls {

extern const std::string generic_reply;

using test_main_func_type = std::function<void (boost::asio::io_service&, uint16_t)>;
int server_test_main(const test_main_func_type& test_main);

} // namespace funtls

#endif