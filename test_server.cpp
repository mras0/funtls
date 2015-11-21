#include <iostream>

#include <util/test.h>
#include <util/base_conversion.h>
#include <util/ostream_adapter.h>
#include <asio_stream_adapter.h>
#include <tls/tls_server.h>

using namespace funtls;

#if defined(OPENSSL_TEST) || defined(SELF_TEST)
#define TESTING
#include <thread>
#endif

#include <x509/x509_io.h>
#include <tls/tls_server_rsa_kex.h>
std::unique_ptr<tls::server_id> get_server_id()
{
#ifdef TESTING
    static const char private_key[] = R"(
-----BEGIN PRIVATE KEY-----
MIICLgIBADANBgkqhkiG9w0BAQEFAASCAhgwggIUAgEAAkEAlUQe0RtIgCXpD0lkH5lco
pG/XrmJShcS462aLhucWEKjX5obKeHJ0NDEzpohGR/vZTTnYsABUp359WovMXD+ZQJAJQ
3gZa4/3AQOrTrOZkk8xx583O3lkUPsuHqZ/lXOp5ipZrDWznK6EcoXVe9IJWzoIDVQdij
ZuuBBIACXNkEPfwJAM45L/6COc4KaPqJlx6lgtDeVxrQtbxBdkTKO9G4ATsYFIno4fSgg
jrd31dGpzgXHckrKWT9u4zsALa8yP1Ed5wJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAADAUalZCSgsIQZuInQ3I4L0LeqTuHh9etZE8ehcuBamhwJAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAADGsPyBsTjUZ1jpPPsFwOi8eik2Tq7baHVG3AL69ya
CswJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACc7dNb7PXFwvlW/9uSHzOs
9oelPYpaRXldYRIRDJNG6wJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABhf
qZJDN4j7pg/q/iUJDrhSP0Ru87iPcejoB0qA2sx5QJAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAACdt2KWqpWDI9KyNS/jMho4UBocb4Ax3E/2TNRLMsRtwg==
-----END PRIVATE KEY-----)";
    static const char certificate[] =
        "MIIBUjCB/aADAgECAgEBMA0GCSqGSIb3DQEBBAUAMBQxEjAQBgNVBAMWCWxvY2Fs"
        "aG9zdDAaFwsxNTExMDgwMDAwWhcLMjUxMTA4MDAwMFowFDESMBAGA1UEAxYJbG9j"
        "YWxob3N0MIGbMA0GCSqGSIb3DQEBAQUAA4GJADCBhQJBAJVEHtEbSIAl6Q9JZB+Z"
        "XKKRv165iUoXEuOtmi4bnFhCo1+aGynhydDQxM6aIRkf72U052LAAVKd+fVqLzFw"
        "/mUCQCUN4GWuP9wEDq06zmZJPMcefNzt5ZFD7Lh6mf5VzqeYqWaw1s5yuhHKF1Xv"
        "SCVs6CA1UHYo2brgQSAAlzZBD38wDQYJKoZIhvcNAQEEBQADQQBMhEJLmCS0dkS8"
        "NKWutTJIaoON+jkLOnIXauB3f2XXQ5J+Bm8HquJHPGx4CGG/5SasJr/RBOzZN6Mv"
        "L3SPTuuT";
#else
    static const char private_key[] = R"(
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCedvFnN8tdl7MP
fAHpl02a+QxXOaCDybGovMZRBQ2rL8Ti7JkEeJiEY4Qz9ZJ9WgQB3Tll9KAueRBz
dmUTOptqSwwx8Ykm3R65lbFljKT04hj3yvCaHg5j+UnzMRIqJ9W8f+EVAGKIG0rp
hTYdpzJpnbSHU8y31Y8THmjgZSyTwSvsP+U1pB/Mt6SSQD7SWIwABveWx6gcCEe0
yE0L5oUISuyR7rRtoBPaSTcL5y3fu2Ez9wc8VVBTBx6wiNqs3BAsBssQADD6sokW
G9AbPchLfkajkb77tX/0GXrnam8oaC5QSOO6SI5vybdIcqAzc5EXN+uEKM/q9vuQ
Sdcr3SelAgMBAAECggEAZPG4DdyI+/Hq6u4/+aGcmiAUMGxRSCJvveGjI3Fop6gi
b7vwLdz0q0EJsl+5FYkGDHn0WnJep7wPMr403O70md18w0Pt7oflTquA+gOCAU0W
QqNQaZzD5gOji/uyapA9o3qC03IPUkywh9mIA5PClW0U1zAWtPSh07gHbwqEPwpK
XVBqfZgHHeqdkli+7uLew00p+kZwDW49CVhDoY8LtaO2a7jebOnm4Mhop+wZjqVy
I0RSOr1Va9l0Zqoh9At7dluxEeI20uts9jkwQcsfaf4rn1M8f4zkHc3GB4ExrOaF
WTfzzBrbtzxWlmryYLhRBlLwcTREKF5M25UizgE2AQKBgQDNMOifb+xGXji0WPnC
BRNa96KDgNYpFfWQUaqle2eSMSuyEtsAMAhlF2tkiwKX7umrOE99bitrZ3jPm+Ye
ekB0C3aKwW+94jxbqYNpnO9s2pIg/jVXCQxaW3SnqfnTrihIMNg0P2gnh0xcdKQM
Kq9tBfeXUkhEyBHX68dBCvP6RQKBgQDFtAn8UqQsZflWOvQdPhatFSwH645jZ+bY
TnSG9JQoW0IuQqTfcr4xbjltDZsp+cDngD0HLJ/Gf33sLrfTVsDlSIZk935qxgiJ
lzyNR1Fd4xdUx6I9Gs4DwWXjE8u/IOq/fhxZ/8c2c8jXVvlTbeEMgRNA9sKP0TnT
ysMB1jj94QKBgAfZZhyrQGOUuSCVAsDcRthE/s9+/zJFJ8akiR2ZceXSwbQnKn+A
VuHfGnmXI7tCJWgqWEgZDconBCUU9qGV1Z9azOcT7T1bSSnMez1wBmyok8x1TP8O
Vo2iT/0V8Hubfuj8DVk6T7arY01qHNhmTZ2jC8ybFi6jZKNY3p9rVtftAoGAMMOw
ttkXf5ADiT5vWgsngre3LZjvfRtyuCXZ3jPTm4Su9UQg8LCXsw+SAJEblaXx6+gY
pX1fR5HI2InJc8pxN9zEsYDOYL3J+04fdGWD71mFNrcrEFFdQVXhsLoARntzC5qq
mZRaadbzUhI021w951yrCBoVcW3VCqV3pitV0WECgYBr/upn5ouDPAjJUZzt14nQ
1daVE0xqt7S1Z2ks46Low1KJyrEzF2tKlnMeV1l9pgPDjHKzCkmYR4SZpUfSq2IU
/Wm8TRASrW+ablQHzPP+TsUSUt6sY/IpxSjfHUHO2w1CKhtLfQU892b9By47qB/L
AZokDceX95yJnwKqa6SzgQ==
-----END PRIVATE KEY-----
)";
static const char certificate[] =
"MIIC+zCCAeOgAwIBAgIJAN1DsbDMyeJ9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV"
"BAMMCWxvY2FsaG9zdDAeFw0xNTA2MTMxOTI2MzJaFw0yNTA2MTAxOTI2MzJaMBQx"
"EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC"
"ggEBAJ528Wc3y12Xsw98AemXTZr5DFc5oIPJsai8xlEFDasvxOLsmQR4mIRjhDP1"
"kn1aBAHdOWX0oC55EHN2ZRM6m2pLDDHxiSbdHrmVsWWMpPTiGPfK8JoeDmP5SfMx"
"Eion1bx/4RUAYogbSumFNh2nMmmdtIdTzLfVjxMeaOBlLJPBK+w/5TWkH8y3pJJA"
"PtJYjAAG95bHqBwIR7TITQvmhQhK7JHutG2gE9pJNwvnLd+7YTP3BzxVUFMHHrCI"
"2qzcECwGyxAAMPqyiRYb0Bs9yEt+RqORvvu1f/QZeudqbyhoLlBI47pIjm/Jt0hy"
"oDNzkRc364Qoz+r2+5BJ1yvdJ6UCAwEAAaNQME4wHQYDVR0OBBYEFNcy1UunV/YV"
"AUnGhgoDcZnOmnNVMB8GA1UdIwQYMBaAFNcy1UunV/YVAUnGhgoDcZnOmnNVMAwG"
"A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEjitUaPNsdB9QMSgcAvzr1L"
"HdVgJQccTsNrqulfvflG3f1XXrKZkzJMArvP4za/BMy/ug9IipIXWpcNTOCfnJbo"
"squiyj/bLLn4ZgLV6wKPW25tbJF6u3FS6+O2MdfyU9SR28y/UoFKVCLBRt3tflph"
"2Xfp7zn3bLw6jgAAVPtJ+BdNwdIaYy14x5pINHum+99iYEvVolPcrPbUlQk7Y3jS"
"sSUcN2EUHHWkG/NfxeMu4A1W4Pxp5u4Zkg9OGlfrF7uTK9kZMOx5nCa7cE75gAb3"
"WMVDXABQK4UaNGxPRhDUAy7u8NqtePjmWGuBzEorqsT9baf7SfdYpGlemBglYWM=";
#endif
    auto pki = x509::read_pem_private_key_from_string(private_key);
    assert(pki.version.as<int>() == 0);
    assert(pki.algorithm.id() == x509::id_rsaEncryption);
    
    return tls::make_rsa_server_id({util::base64_decode(certificate, sizeof(certificate)-1)}, x509::rsa_private_key_from_pki(pki));
}

#ifdef SELF_TEST
#include "https_fetch.h"
#elif defined(OPENSSL_TEST)

// TODO: This should be moved somewhere else...

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

#ifdef WIN32
#include <windows.h>
struct win32_handle_closer {
    using pointer = HANDLE;
    void operator()(HANDLE h) {
        const BOOL closed_ok = CloseHandle(h);
        assert(closed_ok); (void)closed_ok;
    }
};
using win32_handle = std::unique_ptr<HANDLE, win32_handle_closer>;

void throw_system_error(const std::string& what, const DWORD dwErrorCode = GetLastError())
{
    assert(dwErrorCode != ERROR_SUCCESS);
    throw std::system_error(dwErrorCode, std::system_category(), what);
}

class child_process_win32 : public child_process {
public:
    explicit child_process_win32(const std::vector<std::string>& args) {
        std::ostringstream oss;
        for (size_t i = 0; i < args.size(); ++i) {
            if (i) oss << " ";
            oss << args[i];
        }
        auto cmdline = oss.str();

        auto in_pipe = create_inheritable_pipe();
        auto out_pipe = create_inheritable_pipe();

        if (!SetHandleInformation(in_pipe.second.get(), HANDLE_FLAG_INHERIT, 0) || !SetHandleInformation(out_pipe.first.get(), HANDLE_FLAG_INHERIT, 0)) {
            throw_system_error("Could not mark pipe handles non-inheritable");
        }

        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        si.cb         = sizeof(si);
        si.dwFlags    = STARTF_USESTDHANDLES;
        si.hStdInput  = in_pipe.first.get();
        si.hStdOutput = out_pipe.second.get();
        si.hStdError  = out_pipe.second.get();

        PROCESS_INFORMATION pi;
        if (!CreateProcessA(
            nullptr,     // LPCTSTR               lpApplicationName,
            &cmdline[0], // LPTSTR                lpCommandLine,
            nullptr,     // LPSECURITY_ATTRIBUTES lpProcessAttributes,
            nullptr,     // LPSECURITY_ATTRIBUTES lpThreadAttributes,
            TRUE,        // BOOL                  bInheritHandles,
            0,           // DWORD                 dwCreationFlags,
            nullptr,     // LPVOID                lpEnvironment,
            nullptr,     // LPCTSTR               lpCurrentDirectory,
            &si,         // LPSTARTUPINFO         lpStartupInfo,
            &pi          // LPPROCESS_INFORMATION lpProcessInformation
            )) {
            throw_system_error("CreateProcess failed");
        }
        CloseHandle(pi.hThread);
        process_.reset(pi.hProcess);

        child_in_  = std::move(in_pipe.second);
        child_out_ = std::move(out_pipe.first);
    }

    ~child_process_win32() {
        child_in_.reset();
        child_out_.reset();
        if (process_) {
            const DWORD dwWaitRes = WaitForSingleObject(process_.get(), 60*1000);
            if (dwWaitRes != WAIT_OBJECT_0) {
                assert(false);
                std::abort();
            }
        }
    }

private:
    win32_handle process_;
    win32_handle child_in_;
    win32_handle child_out_;

    static std::pair<win32_handle, win32_handle> create_inheritable_pipe() {
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa;
        ZeroMemory(&sa, sizeof(sa));
        sa.bInheritHandle = TRUE;
        if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
            throw_system_error("Error creating pipe");
        }
        return {win32_handle{hRead}, win32_handle{hWrite}};
    }

    virtual bool do_fill_child_out_buffer(std::string& out_buffer) override {
        assert(child_out_);
        char buffer[256];
        DWORD dwRead;
        if (!ReadFile(child_out_.get(), buffer, sizeof(buffer), &dwRead, nullptr)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                return false;
            }
            throw_system_error("Error reading from child stdout");
        }
        assert(dwRead != 0);
        out_buffer += std::string(buffer, buffer + dwRead);
        return true;
    }

    virtual int do_wait() override {
        return 0;
    }

    virtual void do_write(const std::string& data) override {
        assert(child_in_);
        DWORD dwWritten;
        if (!WriteFile(child_in_.get(), data.data(), static_cast<DWORD>(data.size()), &dwWritten, nullptr)) {
            throw_system_error("Error writing to child stdin");
        }
        assert(dwWritten == data.size());
    }

    virtual void do_close_stdin() override {
        assert(child_in_);

        child_in_.reset();
    }
};

std::unique_ptr<child_process> child_process::create(const std::vector<std::string>& args)
{
    return std::unique_ptr<child_process>{new child_process_win32{args}};
}

void send_enter_to_console()
{
    HANDLE hStdIn = CreateFileA("CONIN$", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hStdIn == INVALID_HANDLE_VALUE) {
        throw_system_error("Could not open console");
    }
    win32_handle console_stdin{hStdIn};

    INPUT_RECORD ir[2];
    ir[0].EventType = KEY_EVENT;
    ir[0].Event.KeyEvent.bKeyDown          = TRUE;
    ir[0].Event.KeyEvent.wRepeatCount      = 1;
    ir[0].Event.KeyEvent.wVirtualKeyCode   = VK_RETURN;
    ir[0].Event.KeyEvent.uChar.AsciiChar   = '\r';
    ir[0].Event.KeyEvent.dwControlKeyState = 0;
    ir[1].EventType = KEY_EVENT;
    ir[1].Event.KeyEvent.bKeyDown          = FALSE;
    ir[1].Event.KeyEvent.wRepeatCount      = 0;
    ir[1].Event.KeyEvent.wVirtualKeyCode   = VK_RETURN;
    ir[1].Event.KeyEvent.uChar.AsciiChar   = '\r';
    ir[1].Event.KeyEvent.dwControlKeyState = 0;
    DWORD cWritten;
    if (!WriteConsoleInputA(console_stdin.get(), ir, _countof(ir), &cWritten)) {
        throw_system_error("Error writing to console input");
    }
    assert(cWritten == _countof(ir));
}

#else
#include <unistd.h>
#include <sys/wait.h>

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
        std::vector<char*> argv(args.size());
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

#endif
#endif
const std::string generic_reply = "Content-type: text/ascii\r\n\r\nHello world!\r\n";

std::shared_ptr<util::ostream_adapter> make_log(const std::string& name)
{
    return std::make_shared<util::ostream_adapter>([name](const std::string& s) { std::cout << name + ": " + s; });
}

void main_loop(std::shared_ptr<util::ostream_adapter> log, util::async_result<std::shared_ptr<tls::tls_base>> async_self)
{
    auto self = async_self.get();
    self->recv_app_data(
        [self, log](util::async_result<std::vector<uint8_t>> async_data) {
        const auto data = async_data.get();
        (*log) << "Got app data: " << std::string(data.begin(), data.end());
        self->send_app_data(std::vector<uint8_t>(generic_reply.begin(), generic_reply.end()), [self, log](util::async_result<void> res) {
            res.get();
            // self->main_loop();
        });
    });
}



int main(int argc, char* argv[])
{
    int wanted_port = 0;
    if (argc > 1) {
        std::istringstream iss(argv[1]);
        if (!(iss >> wanted_port) || wanted_port < 0 || wanted_port > 65535) {
            std::cerr << "Invalid port " << argv[1] << "" << std::endl;
            return 1;
        }
    }
    boost::asio::io_service        io_service;
    boost::asio::ip::tcp::acceptor acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), static_cast<uint16_t>(wanted_port)));

    struct accept_state {
        accept_state(boost::asio::io_service& io_service) : socket(io_service) {
        }
        boost::asio::ip::tcp::socket socket;
    };

    auto server_id = get_server_id();

    std::function<void (void)> start_accept = [&acceptor, &start_accept, &server_id] {
        auto state = std::make_shared<accept_state>(acceptor.get_io_service());
        acceptor.async_accept(state->socket,
            [state, &start_accept, &server_id] (const boost::system::error_code& ec) {
                if (ec) {
                    std::cout << "Accept failed: " << ec << std::endl;
                } else {
                    std::ostringstream oss;
                    oss << state->socket.remote_endpoint();
                    auto log = make_log(oss.str());
                    tls::perform_handshake_with_client(make_tls_stream(std::move(state->socket)), {server_id.get()}, std::bind(&main_loop, log, std::placeholders::_1), log.get());
                }
                start_accept();
            });
    };

    start_accept();
    std::cout << "Server running: " << acceptor.local_endpoint() << std::endl;

#ifdef TESTING

    unsigned short port = acceptor.local_endpoint().port();
    std::exception_ptr eptr = nullptr;
    std::thread client_thread([&] {
            boost::asio::io_service::work work(io_service); // keep the io_service running as long as the thread does

            try {
#ifdef OPENSSL_TEST
                FUNTLS_CHECK_BINARY(argc, ==, 3, "Invalid arguments to test");
                const std::string cipher = "RC4-MD5";
                std::string openssl = argv[2];
#ifdef WIN32
                std::replace(begin(openssl), end(openssl), '/', '\\');
#endif
                auto openssl_child_process = child_process::create({
                    openssl,
                    "s_client",
                    "-tls1_2",   // We require TLS1.2 (this will also catch us testing against ancient versions of openssl
                    "-debug",
                    "-msg",
                    "-cipher",
                    cipher,
                    "-connect",
                    "localhost:" + std::to_string(port)
                });

                openssl_child_process->write("HELLO WORLD\r\n");
                openssl_child_process->close_stdin();

#ifdef WIN32
                // HACK for openssl
                send_enter_to_console();
#endif
                for (std::string s; openssl_child_process->read_line(s); ) {
                    io_service.post([s] {
                            std::cout << "[openssl] " << s;
                            });
                }
                const auto wait_result = openssl_child_process->wait();
                io_service.post([wait_result] {
                    FUNTLS_CHECK_BINARY(wait_result, ==, 0, "Wait failed");
                    std::cout << "openssl exited OK\n";
                    });
#elif defined(SELF_TEST)
                x509::trust_store ts;

                const std::vector<tls::cipher_suite> cipher_suites{
                    //tls::cipher_suite::ecdhe_ecdsa_with_aes_256_gcm_sha384,
                    //tls::cipher_suite::ecdhe_ecdsa_with_aes_128_gcm_sha256,

                    tls::cipher_suite::ecdhe_rsa_with_aes_256_cbc_sha,
                    tls::cipher_suite::ecdhe_rsa_with_aes_128_cbc_sha,

                    tls::cipher_suite::ecdhe_rsa_with_aes_256_gcm_sha384,
                    tls::cipher_suite::ecdhe_rsa_with_aes_128_gcm_sha256,

                    tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha256,
                    tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha256,
                    tls::cipher_suite::dhe_rsa_with_aes_256_cbc_sha,
                    tls::cipher_suite::dhe_rsa_with_aes_128_cbc_sha,
                    tls::cipher_suite::dhe_rsa_with_3des_ede_cbc_sha,

                    tls::cipher_suite::rsa_with_aes_256_gcm_sha384,
                    tls::cipher_suite::rsa_with_aes_128_gcm_sha256,
                    tls::cipher_suite::rsa_with_aes_256_cbc_sha256,
                    tls::cipher_suite::rsa_with_aes_128_cbc_sha256,
                    tls::cipher_suite::rsa_with_aes_256_cbc_sha,
                    tls::cipher_suite::rsa_with_aes_128_cbc_sha,
                    tls::cipher_suite::rsa_with_3des_ede_cbc_sha,
                    tls::cipher_suite::rsa_with_rc4_128_sha,
                    tls::cipher_suite::rsa_with_rc4_128_md5,
                };

                for (const auto& cs: cipher_suites) {
                    io_service.post([cs] { std::cout << "=== Testing " << cs << " ===" << std::endl; });
                    std::string res;
                    util::ostream_adapter fetch_log{[&io_service](const std::string& s) { io_service.post([s] { std::cout << "Client: " << s; }); }};
                    https_fetch("localhost", std::to_string(port), "/", {cs}, ts, [&res](const std::vector<uint8_t>& data) {
                        res.insert(res.end(), data.begin(), data.end());
                    }, fetch_log);
                    io_service.post([res] {
                        std::cout << "Got result: \"" << res << "\"" << std::endl;
                        FUNTLS_ASSERT_EQUAL(generic_reply, res);
                    });
                }
#else
#error What are we testing???
#endif
            } catch (...) {
                eptr = std::current_exception();
            }
            io_service.post([&io_service] { io_service.stop(); });
    });
#endif

    int retval = 1;
    try {
        io_service.run();
#ifdef TESTING
        if (eptr) std::rethrow_exception(eptr);
#endif
        retval = 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
    }
#ifdef TESTING
    client_thread.join();
#endif
    return retval;
}

