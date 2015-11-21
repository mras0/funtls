#include "child_process.h"
#include "win32_util.h"
#include <windows.h>
#include <cassert>
#include <sstream>

namespace funtls { namespace util {

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

} } // namespace funtls::util
