#include "ssh.h"
#include <sstream>
#include <algorithm>
#include <util/test.h>

namespace {

constexpr bool legal_us_ascii(char c) {
    return c >= 32 && c < 127;
}

}

namespace funtls { namespace ssh {

std::ostream& operator<<(std::ostream& os, message_type mt)
{
    switch (mt) {
    case message_type::disconnect:                 return os << "SSH_MSG_DISCONNECT";
    case message_type::ignore:                     return os << "SSH_MSG_IGNORE";
    case message_type::unimplemented:              return os << "SSH_MSG_UNIMPLEMENTED";
    case message_type::debug:                      return os << "SSH_MSG_DEBUG";
    case message_type::service_request:            return os << "SSH_MSG_SERVICE_REQUEST";
    case message_type::service_accept:             return os << "SSH_MSG_SERVICE_ACCEPT";
    case message_type::kexinit:                    return os << "SSH_MSG_KEXINIT";
    case message_type::newkeys:                    return os << "SSH_MSG_NEWKEYS";
    case message_type::kexdh_init:                 return os << "SSH_MSG_KEXDH_INIT";
    case message_type::kexdh_reply:                return os << "SSH_MSG_KEXDH_REPLY";
    case message_type::userauth_request:           return os << "SSH_MSG_USERAUTH_REQUEST";
    case message_type::userauth_failure:           return os << "SSH_MSG_USERAUTH_FAILURE";
    case message_type::userauth_success:           return os << "SSH_MSG_USERAUTH_SUCCESS";
    case message_type::userauth_banner:            return os << "SSH_MSG_USERAUTH_BANNER";
    case message_type::userauth_pk_ok:             return os << "SSH_MSG_USERAUTH_PK_OK";
    case message_type::global_request:             return os << "SSH_MSG_GLOBAL_REQUEST";
    case message_type::request_success:            return os << "SSH_MSG_REQUEST_SUCCESS";
    case message_type::request_failure:            return os << "SSH_MSG_REQUEST_FAILURE";
    case message_type::channel_open:               return os << "SSH_MSG_CHANNEL_OPEN";
    case message_type::channel_open_confirmation:  return os << "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
    case message_type::channel_open_failure:       return os << "SSH_MSG_CHANNEL_OPEN_FAILURE";
    case message_type::channel_window_adjust:      return os << "SSH_MSG_CHANNEL_WINDOW_ADJUST";
    case message_type::channel_data:               return os << "SSH_MSG_CHANNEL_DATA";
    case message_type::channel_extended_data:      return os << "SSH_MSG_CHANNEL_EXTENDED_DATA";
    case message_type::channel_eof:                return os << "SSH_MSG_CHANNEL_EOF";
    case message_type::channel_close:              return os << "SSH_MSG_CHANNEL_CLOSE";
    case message_type::channel_request:            return os << "SSH_MSG_CHANNEL_REQUEST";
    case message_type::channel_success:            return os << "SSH_MSG_CHANNEL_SUCCESS";
    case message_type::channel_failure:            return os << "SSH_MSG_CHANNEL_FAILURE";
    }
    return os << "Unknown SSH message type " << static_cast<unsigned>(mt);
}

std::ostream& operator<<(std::ostream& os, disconnect_reason dc)
{
    switch  (dc) {
    case disconnect_reason::host_not_allowed_to_connect:     return os << "SSH_DISONNECT_HOST_NOT_ALLOWED_TO_CONNECT";
    case disconnect_reason::protocol_error:                  return os << "SSH_DISONNECT_PROTOCOL_ERROR";
    case disconnect_reason::key_exchange_failed:             return os << "SSH_DISONNECT_KEY_EXCHANGE_FAILED";
    case disconnect_reason::reserved:                        return os << "SSH_DISONNECT_RESERVED";
    case disconnect_reason::mac_error:                       return os << "SSH_DISONNECT_MAC_ERROR";
    case disconnect_reason::compression_error:               return os << "SSH_DISONNECT_COMPRESSION_ERROR";
    case disconnect_reason::service_not_available:           return os << "SSH_DISONNECT_SERVICE_NOT_AVAILABLE";
    case disconnect_reason::protocol_version_not_supported:  return os << "SSH_DISONNECT_PROTOCOL_VERSION_NOT_SUPPORTED";
    case disconnect_reason::host_key_not_verifiable:         return os << "SSH_DISONNECT_HOST_KEY_NOT_VERIFIABLE";
    case disconnect_reason::connection_lost:                 return os << "SSH_DISONNECT_CONNECTION_LOST";
    case disconnect_reason::by_application:                  return os << "SSH_DISONNECT_BY_APPLICATION";
    case disconnect_reason::too_many_connections:            return os << "SSH_DISONNECT_TOO_MANY_CONNECTIONS";
    case disconnect_reason::auth_cancelled_by_user:          return os << "SSH_DISONNECT_AUTH_CANCELLED_BY_USER";
    case disconnect_reason::no_more_auth_methods_available:  return os << "SSH_DISONNECT_NO_MORE_AUTH_METHODS_AVAILABLE";
    case disconnect_reason::illegal_user_name:               return os << "SSH_DISONNECT_ILLEGAL_USER_NAME";
    }
    return os << "Unknown SSH disconnect reason " << static_cast<unsigned>(dc);
}

std::vector<uint8_t> get_string(util::buffer_view& buf)
{
    const uint32_t length = util::get_be_uint32(buf);
    FUNTLS_CHECK_BINARY(length, <=, buf.remaining(), "String exceeds buffer length");
    std::vector<uint8_t> str(length);
    if (length) {
        buf.read(str.data(), str.size());
    }
    return str;
}

bool name_list::contains(const std::string& name) const {
    return std::find(begin(), end(), name) != end();
}

std::ostream& operator<<(std::ostream& os, const name_list& nl)
{
    bool first = true;
    for (const auto& e : nl) {
        if (first) {
            first = false;
        } else {
            os << ",";
        }
        os << e;
    }
    return os;
}

name_list name_list::from_string(const std::vector<uint8_t>& s)
{
    if (s.empty()) {
        return {};
    }

    auto illegal_char = std::find_if(s.begin(), s.end(), [](char c) { return !legal_us_ascii(c); });
    if (illegal_char != s.end()) {
        FUNTLS_CHECK_FAILURE("Invalid name list '" + std::string(s.begin(), s.end()) + "'");
    }

    std::vector<std::string> res;
    size_t last_start = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == ',') {
            res.emplace_back(&s[last_start], &s[i]);
            last_start = i + 1;
        }
    }
    if (last_start < s.size()) {
        res.emplace_back(s.begin() + last_start, s.end());
    } else if (last_start == s.size()) {
        FUNTLS_CHECK_FAILURE("Invalid name list '" + std::string(s.begin(), s.end()) + "'");
    }
    assert(!res.empty());
    auto empty_string = std::find_if(res.begin(), res.end(), [](const std::string& s) { return s.empty(); });
    if (empty_string != res.end()) {
        FUNTLS_CHECK_FAILURE("Invalid name list '" + std::string(s.begin(), s.end()) + "'");
    }
    return name_list{res};
}

} } // namespace funtls::ssh
