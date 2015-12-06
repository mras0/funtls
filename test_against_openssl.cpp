#include <iostream>
#include <boost/asio.hpp>
#include <util/test.h>
#include <util/child_process.h>
#include <util/win32_util.h>
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

void openssl_test_client(boost::asio::io_service& io_service, uint16_t port)
{
    const std::string cipher = "RC4-MD5";
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
}

int main()
{
    return server_test_main(&openssl_test_client);
}