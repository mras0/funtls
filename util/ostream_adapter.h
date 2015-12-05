#ifndef FUNTLS_UTIL_OSTREAM_ADAPTER_H_INCLUDED
#define FUNTLS_UTIL_OSTREAM_ADAPTER_H_INCLUDED

#include <ostream>
#include <memory>
#include <functional>

namespace funtls { namespace util {

class ostream_adapter : public std::ostream {
public:
    using output_func_type = std::function<void (const std::string&)>;
    explicit ostream_adapter(const output_func_type& out_func);
    ~ostream_adapter();
private:
    std::unique_ptr<std::streambuf> buffer_;
};

} } // namespace funtls::util

#endif

