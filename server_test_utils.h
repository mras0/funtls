#ifndef FUNTLS_SERVER_TEST_UTILS_H_INCLUDED
#define FUNTLS_SERVER_TEST_UTILS_H_INCLUDED

#include <functional>
#include <x509/x509.h>

namespace funtls {

extern const std::string generic_reply;

x509::certificate server_test_certificate();

using exec_in_main_thread_func_type = std::function<void (std::function<void (void)>)>;
using test_main_func_type = std::function<void (exec_in_main_thread_func_type, uint16_t)>;
int server_test_main(const test_main_func_type& test_main);

} // namespace funtls

#endif