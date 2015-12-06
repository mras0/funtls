#include "buffer.h"
#include "test.h"
#include <sstream>

namespace funtls { namespace util {

void buffer_view::out_of_buffer(size_t num_bytes) const
{
    std::ostringstream ss;
    ss << "Out of buffer. " << num_bytes << " requested " << (size_ - index_) << " available.";
    FUNTLS_CHECK_FAILURE(ss.str());
}

} } // namespace funtls::util
