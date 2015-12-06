#include "child_process.h"

#include <unistd.h>
#include <sys/wait.h>

#include <cassert>
#include <cstdlib>
#include <system_error>
#include <stdexcept>

namespace funtls { namespace util {

void throw_system_error(const std::string& what, int error = errno)
{
    assert(error);
    throw std::system_error(error, std::system_category(), what);
}


class posix_file {
public:
    explicit posix_file(int fd = -1) : fd_(fd) {}

    posix_file(posix_file&& f) : fd_(-1) {
        std::swap(fd_, f.fd_);
    }

    posix_file(const posix_file&) = delete;

    posix_file& operator=(posix_file&& rhs) {
        close();
        std::swap(fd_, rhs.fd_);
        return *this;
    }

    posix_file& operator=(const posix_file&) = delete;

    ~posix_file() {
        close();
    }

    int native_handle() {
        return fd_;
    }

    void close() {
        if (*this) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    explicit operator bool() const {
        return fd_ != -1;
    }

private:
    int fd_;
};

class posix_process {
public:
    explicit posix_process(pid_t pid = -1) : pid_(pid) {}

    posix_process(posix_process&& f) : pid_(-1) {
        std::swap(pid_, f.pid_);
    }

    posix_process(const posix_process&) = delete;

    posix_process& operator=(posix_process&& rhs) {
        std::swap(pid_, rhs.pid_);
        return *this;
    }

    ~posix_process() {
        wait();
    }

    int wait() {
        int status = 0;
        if (*this) {
            if (waitpid(pid_, &status, 0) == -1) {
                throw_system_error("waitpid failed");
            }
            pid_ = -1;
        }
        return status;
    }

    explicit operator bool() const {
        return pid_ != -1;
    }

private:
    pid_t pid_;
};

class child_process_posix : public child_process {
public:
    explicit child_process_posix(const std::vector<std::string>& args) {
        std::vector<char*> argv(args.size() + 1); // argv must be null terminated
        for (size_t i = 0; i < args.size(); ++i) {
            argv[i] = const_cast<char*>(args[i].c_str());
        }

        signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE in child and parent

                                  // Based on http://www.microhowto.info/howto/capture_the_output_of_a_child_process_in_c.html
        auto in_pipe  = create_pipe();
        auto out_pipe = create_pipe();

        pid_t pid = fork();
        if (pid == -1) {
            throw_system_error("fork");
        } else if (pid == 0) {
            while ((dup2(in_pipe.first.native_handle(), STDIN_FILENO) == -1) && (errno == EINTR)) {}
            while ((dup2(out_pipe.second.native_handle(), STDOUT_FILENO) == -1) && (errno == EINTR)) {}
            in_pipe.first.close();
            in_pipe.second.close();
            out_pipe.first.close();
            out_pipe.second.close();
            execv(argv[0], &argv[0]);
            perror("execl");
            _exit(1);
        }
        child_in_  = std::move(in_pipe.second);
        child_out_ = std::move(out_pipe.first);
    }

    ~child_process_posix() {
        child_in_.close();
        child_out_.close();
        wait();
    }

private:
    posix_process child_;
    posix_file    child_in_;
    posix_file    child_out_;
    std::string   child_out_buffer_;

    static std::pair<posix_file, posix_file> create_pipe() {
        int fds[2];
        if (pipe(fds) == -1) {
            throw_system_error("pipe() failed");
        }
        return { posix_file{fds[0]}, posix_file{fds[1]} };
    }

    virtual int do_wait() override {
        return child_.wait();
    }

    virtual bool do_fill_child_out_buffer(std::string& out_buffer) override {
        char buffer[256];

        const int r = ::read(child_out_.native_handle(), buffer, sizeof(buffer));
        if (r > 0) {
            out_buffer += std::string(buffer, buffer + r);
            return true;
        } else if (r == 0) {
            return false;
        }
        throw_system_error("read failed");
        std::abort();
    }

    virtual void do_write(const std::string& data) override {
        assert(child_in_);
        const int r = ::write(child_in_.native_handle(), data.data(), data.size());
        if (r == -1) {
            throw_system_error("write failed");
        }
    }

    virtual void do_close_stdin() override {
        assert(child_in_);
        child_in_.close();
    }
};

std::unique_ptr<child_process> child_process::create(const std::vector<std::string>& args)
{
    return std::unique_ptr<child_process>{new child_process_posix{args}};
}

} } // namespace funtls::util
