#ifndef FUNTLS_SERVER_TEST_UTILS_H_INCLUDED
#define FUNTLS_SERVER_TEST_UTILS_H_INCLUDED

#include <functional>

namespace funtls {

extern const std::string generic_reply;

using exec_in_main_thread_func_type = std::function<void (std::function<void (void)>)>;
using test_main_func_type = std::function<void (exec_in_main_thread_func_type, uint16_t)>;
int server_test_main(const test_main_func_type& test_main);

} // namespace funtls

#endif