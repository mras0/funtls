#include <iostream>
#include <sstream>

#include <util/async_result.h>
#include <util/base_conversion.h>
#include <util/ostream_adapter.h>
#include <x509/x509_io.h>
#include <tls/tls_server_rsa_kex.h>

#include "tcp_tls_server.h"

#include <boost/asio.hpp>

using namespace funtls;

std::unique_ptr<tls::server_id> get_server_id()
{
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
    auto pki = x509::read_pem_private_key_from_string(private_key);
    assert(pki.version.as<int>() == 0);
    assert(pki.algorithm.id() == x509::id_rsaEncryption);
    
    return tls::make_rsa_server_id({util::base64_decode(certificate, sizeof(certificate)-1)}, x509::rsa_private_key_from_pki(pki));
}

std::shared_ptr<std::ostream> make_log(const std::string& name)
{
    return std::make_shared<util::ostream_adapter>([name](const std::string& s) { std::cout << name + ": " + s; });
}

void on_error(std::shared_ptr<std::ostream> log, std::exception_ptr error)
{
    try {
        std::rethrow_exception(error);
    } catch (const std::exception& e) {
        *log << e.what() << std::endl;
    } catch (...) {
        *log << "Unknown exception caught" << std::endl;
    }
}


void main_loop(util::async_result<std::shared_ptr<tls::tls_base>> async_self, std::shared_ptr<std::ostream> log)
{
    auto handle_error = std::bind(&on_error, log, std::placeholders::_1);
    try {
        auto self = async_self.get();

        self->recv_app_data(util::wrapped(
            [self, log, handle_error](std::vector<uint8_t>&& data) {
                (*log) << "Got app data: " << std::string(data.begin(), data.end());
                const std::string generic_reply = "HTTP/1.1 200 OK\r\nContent-type: text/plain\r\n\r\nHello world!\n";
                self->send_app_data(std::vector<uint8_t>(generic_reply.begin(), generic_reply.end()), util::wrapped([self]() {/* self->main_loop(); */ }, handle_error));
        }, handle_error));
    } catch (...) {
        handle_error(std::current_exception());
    }
}

int main(int argc, char* argv[])
{
    try {
        int wanted_port = 0;
        if (argc > 1) {
            std::istringstream iss(argv[1]);
            if (!(iss >> wanted_port) || wanted_port < 0 || wanted_port > 65535) {
                std::cerr << "Invalid port " << argv[1] << "" << std::endl;
                return 1;
            }
        }

        boost::asio::io_service  io_service;
        auto server  = tcp_tls_server::create(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), static_cast<uint16_t>(wanted_port)), get_server_id(), &make_log, &main_loop);

        std::cout << "Server running: " << server->local_endpoint() << std::endl;

        io_service.run();

        std::cout << "Server exiting\n";

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
        return 1;
    }
    return 0;
}