#ifndef FUNTLS_SSH_SSH_H_INCLUDED
#define FUNTLS_SSH_SSH_H_INCLUDED

#include <stdint.h>
#include <iosfwd>
#include <util/buffer.h>
#include <vector>
#include <string>

namespace funtls { namespace ssh {

// Message numbers are defined in RFC4250

enum class message_type : uint8_t {
//      Transport layer protocol:
//        1 to 19    Transport layer generic (e.g., disconnect, ignore,
//                   debug, etc.)
    disconnect                   =   1,
    ignore                       =   2,
    unimplemented                =   3,
    debug                        =   4,
    service_request              =   5,
    service_accept               =   6,
//        20 to 29   Algorithm negotiation
    kexinit                      =  20,
    newkeys                      =  21,
//        30 to 49   Key exchange method specific (numbers can be reused
//                   for different authentication methods)
    kexdh_init                   =  30,
    kexdh_reply                  =  31,
//      User authentication protocol:
//        50 to 59   User authentication generic
    userauth_request             =  50,
    userauth_failure             =  51,
    userauth_success             =  52,
    userauth_banner              =  53,
//        60 to 79   User authentication method specific (numbers can be
//                   reused for different authentication methods)
    userauth_pk_ok               =  60,
//      Connection protocol:
//        80 to 89   Connection protocol generic
    global_request               =  80,
    request_success              =  81,
    request_failure              =  82,
//        90 to 127  Channel related messages
    channel_open                 =  90,
    channel_open_confirmation    =  91,
    channel_open_failure         =  92,
    channel_window_adjust        =  93,
    channel_data                 =  94,
    channel_extended_data        =  95,
    channel_eof                  =  96,
    channel_close                =  97,
    channel_request              =  98,
    channel_success              =  99,
    channel_failure              = 100,
//      Reserved for client protocols:
//        128 to 191 Reserved
//      Local extensions:
//        192 to 255 Local extensions
};

std::ostream& operator<<(std::ostream& os, message_type mt);

constexpr uint32_t extended_data_stderr = 1;

enum class disconnect_reason : uint32_t {
    host_not_allowed_to_connect       =  1,
    protocol_error                    =  2,
    key_exchange_failed               =  3,
    reserved                          =  4,
    mac_error                         =  5,
    compression_error                 =  6,
    service_not_available             =  7,
    protocol_version_not_supported    =  8,
    host_key_not_verifiable           =  9,
    connection_lost                   = 10,
    by_application                    = 11,
    too_many_connections              = 12,
    auth_cancelled_by_user            = 13,
    no_more_auth_methods_available    = 14,
    illegal_user_name                 = 15,
};

std::ostream& operator<<(std::ostream& os, disconnect_reason mt);

std::vector<uint8_t> get_string(util::buffer_view& buf);

class name_list {
public:
    name_list() {}
    explicit name_list(const std::vector<std::string>& sv) : repr_(sv) {}

    std::vector<std::string>::const_iterator begin() const {
        return repr_.begin();
    }

    std::vector<std::string>::const_iterator end() const {
        return repr_.end();
    }

    bool operator==(const name_list& rhs) const {
        return repr_ == rhs.repr_;
    }

    bool contains(const std::string& name) const;

    // Parse comma seperated name list
    static name_list from_string(const std::vector<uint8_t>& s);
    static name_list from_buffer(util::buffer_view& b) {
        return from_string(get_string(b));
    }

private:
    std::vector<std::string> repr_;
};

inline bool operator!=(const name_list& lhs, const name_list& rhs) {
    return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& os, const name_list& nl);

// Assumes enough precision is available in IntType
template<typename IntType>
IntType string_to_int(const std::vector<uint8_t>& s) {
    if (s.empty()) {
        return 0;
    }
    IntType res = static_cast<int8_t>(s[0]);
    for (size_t i = 1, len = s.size(); i < len; ++i) {
        res <<= 8;
        res |= s[i];
    }
    if (!res) {
        // Zero MUST be represented as the empty string
        throw std::runtime_error("Illegal representation of zero");
    }
    return res;
}

} } // namespace funtls::ssh

#endif
