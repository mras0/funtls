#ifndef FUNTLS_UTIL_CHILD_PROCESS_H_INCLUDED
#define FUNTLS_UTIL_CHILD_PROCESS_H_INCLUDED

#include <string>
#include <memory>
#include <vector>

namespace funtls { namespace util {

class child_process {
public:
    virtual ~child_process() {}

    int wait() {
        return do_wait();
    }

    bool read_line(std::string& line) {
        for (;;) {
            const auto new_line_pos = child_out_buffer_.find('\n');
            if (new_line_pos == std::string::npos) {
                if (!do_fill_child_out_buffer(child_out_buffer_)) {
                    return false;
                }
            } else {
                line = child_out_buffer_.substr(0, new_line_pos + 1);
                child_out_buffer_.erase(child_out_buffer_.begin(), child_out_buffer_.begin() + new_line_pos + 1);
                return true;
            }
        }
    }

    void write(const std::string& data) {
        do_write(data);
    }

    void close_stdin() {
        do_close_stdin();
    }

    static std::unique_ptr<child_process> create(const std::vector<std::string>& args);

private:
    std::string  child_out_buffer_;

    virtual int do_wait() = 0;
    virtual bool do_fill_child_out_buffer(std::string& buffer) = 0;
    virtual void do_write(const std::string& data) = 0;
    virtual void do_close_stdin() = 0;
};

} } // namespace funtls::util
#endif