#include <iostream>
#include <boost/asio.hpp>
#include <util/test.h>
#include <util/child_process.h>
#include <util/win32_util.h>
#include <future>
#include "server_test_utils.h"

using namespace funtls;

#ifdef WIN32
#include <Windows.h>
void send_enter_to_console()
{
    HANDLE hStdIn = CreateFileA("CONIN$", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hStdIn == INVALID_HANDLE_VALUE) {
        util::throw_system_error("Could not open console");
    }
    util::win32_handle console_stdin{hStdIn};

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
        util::throw_system_error("Error writing to console input");
    }
    assert(cWritten == _countof(ir));
}
#endif

void close_stdin(util::child_process& p)
{
    p.close_stdin();
#ifdef WIN32
    // HACK for openssl
    send_enter_to_console();
#endif
}

void openssl_test_client(boost::asio::io_service& io_service, uint16_t port)
{
    const std::vector<std::string> ciphers {
        "RC4-MD5",
        "DES-CBC3-SHA",
        "DHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES128-GCM-SHA256",
//      "ECDHE-ECDSA-AES256-GCM-SHA384" // ECDHE-ECDSA key exchange isn't supported by the server code yet
    };

    for (const auto& cipher : ciphers) {
        io_service.post([cipher] { std::cout << "=== Testing " << cipher << " ===" << std::endl; });

        auto openssl_child_process = util::child_process::create({
            OPENSSL_EXE,
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
        close_stdin(*openssl_child_process);

        std::string all_output_from_openssl;
        for (std::string s; openssl_child_process->read_line(s); ) {
            all_output_from_openssl += s;
            io_service.post([s] {
                std::cout << "[openssl] " << s;
            });
        }

        const auto wait_result = openssl_child_process->wait();

        // Make sure we synchronize with the main thread before proceeding to the next test
        sync_flag_provider provider;
        auto observer = provider.get_observer();
        io_service.post([=, &provider] {
            sync_flag_provider p{std::move(provider)};
            FUNTLS_CHECK_BINARY(wait_result, ==, 0, "Wait failed");
            FUNTLS_CHECK_BINARY(all_output_from_openssl.find("Cipher is " + cipher), !=, std::string::npos, "Wrong cipher used? Expected " + cipher);
            FUNTLS_CHECK_BINARY(all_output_from_openssl.find(generic_reply), !=, std::string::npos, "Expected reply not found in output.");
            p.signal();
        });
        observer();
    }
}

int main()
{
    return server_test_main(&openssl_test_client);
}