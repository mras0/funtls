#ifndef FUNTLS_SERVER_TEST_UTILS_H_INCLUDED
#define FUNTLS_SERVER_TEST_UTILS_H_INCLUDED

#include <functional>
#include <memory>

namespace boost { namespace asio {
class io_service;
} } // namespace boost::asio

namespace funtls {

extern const std::string generic_reply;

class sync_shared_state;

class sync_flag_provider {
public:
    explicit sync_flag_provider();
    sync_flag_provider(const sync_flag_provider&) = delete;
    sync_flag_provider& operator=(const sync_flag_provider&) = delete;
    sync_flag_provider(sync_flag_provider&&);
    sync_flag_provider& operator=(sync_flag_provider&&);
    ~sync_flag_provider();

    void signal();

    std::function<void(void)> get_observer();

private:
    std::shared_ptr<sync_shared_state> state_;
};

using test_main_func_type = std::function<void (boost::asio::io_service&, uint16_t)>;
int server_test_main(const test_main_func_type& test_main);

} // namespace funtls

#endif