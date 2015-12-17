#include "ostream_adapter.h"
#include <sstream>

using namespace funtls::util;

namespace {

class ostream_adapter_bufimpl : public std::stringbuf {
public:
    explicit ostream_adapter_bufimpl(const ostream_adapter::output_func_type& out_func) : out_func_(out_func) {
    }

    ~ostream_adapter_bufimpl() {
        if (!str().empty()) {
            pubsync();
        }
    }

    int sync() {
        out_func_(str());
        str("");
        return 0;
    }
private:
    ostream_adapter::output_func_type out_func_;
};

} // unnamed namespace

namespace funtls { namespace util {

// This will leak if ostream's constructor throws, but that's a concern for another day
ostream_adapter::ostream_adapter(const output_func_type& out_func) : std::ostream(nullptr), buffer_(new ostream_adapter_bufimpl(out_func))
{
    rdbuf(buffer_.get());
}

ostream_adapter::~ostream_adapter()
{
    rdbuf(nullptr);
}

} } // namespace funtls::util

