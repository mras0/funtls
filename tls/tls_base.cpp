#include <tls/tls_base.h>
#include <util/test.h>
#include <util/base_conversion.h>

#include <iostream>

using namespace funtls;
using util::wrapped;
using util::do_wrapped;

namespace funtls { namespace tls {

tls_base::~tls_base() = default;

void tls_base::send_app_data(const std::vector<uint8_t>& d, const app_data_sent_handler& handler)
{
    send_record(content_type::application_data, d, handler);
}

void tls_base::recv_app_data(const app_data_handler& handler)
{
    recv_record(wrapped(
        [handler] (record&& record) {
            FUNTLS_CHECK_BINARY(record.type, ==, content_type::application_data, "Unexpected content type");
            handler(std::move(record.fragment));
        }, handler));
}

void tls_base::send_record(tls::content_type content_type, const std::vector<uint8_t>& plaintext, const done_handler& handler)
{
    do_wrapped([&] {
        collapse_pending();
        FUNTLS_CHECK_BINARY(plaintext.size(), >=, 1, "Illegal plain text size"); // TODO: Empty plaintext is legal for app data
        FUNTLS_CHECK_BINARY(plaintext.size(), <=, record::max_plaintext_length, "Illegal plain text size");

        if (content_type == tls::content_type::handshake) {
            append_to_buffer(handshake_messages_, plaintext);
        }

        // Compression would happen here

        // Do encryption
        const auto ver_buffer = verification_buffer(encrypt_sequence_number_++, content_type, current_protocol_version_, plaintext.size());
        const auto fragment  = encrypt_cipher_->process(plaintext, ver_buffer);
        FUNTLS_CHECK_BINARY(fragment.size(), <=, record::max_ciphertext_length, "Illegal fragment size");

        send_buffer_.clear();
        append_to_buffer(send_buffer_, content_type);
        append_to_buffer(send_buffer_, current_protocol_version_);
        append_to_buffer(send_buffer_, uint16(fragment.size()));
        assert(send_buffer_.size() == 5);
        append_to_buffer(send_buffer_, fragment);
    }, handler);

    stream_->write(send_buffer_, handler);
}

void tls_base::recv_record(const recv_record_handler& handler)
{
    do_wrapped([&] {
        collapse_pending();
        recv_buffer_.resize(5);
    }, handler);
    stream_->read(recv_buffer_, wrapped([this, handler]() {
                do_recv_record_content(handler);
            }, handler));
}

void tls_base::send_handshake(const handshake& handshake, const done_handler& handler)
{
    do_wrapped([&] {
        assert(handshake.content_type == content_type::handshake);
        std::vector<uint8_t> payload_buffer;
        append_to_buffer(payload_buffer, handshake);
        send_record(handshake.content_type, payload_buffer, handler);
    }, handler);
}

void tls_base::read_handshake(const recv_handshake_handler& handler)
{
    recv_record(wrapped([this, handler](record&& record) {
            FUNTLS_CHECK_BINARY(record.type, ==, content_type::handshake, "Invalid content type");

            util::buffer_view frag_buf{&record.fragment[0], record.fragment.size()};
            handshake handshake;
            from_bytes(handshake, frag_buf);
            if (frag_buf.remaining()) {
                FUNTLS_CHECK_FAILURE("Unread handshake data. Fragment: " + util::base16_encode(record.fragment));
            }
            handler(std::move(handshake));
        }, handler));
}

void tls_base::set_pending_ciphers(cipher_parameters&& client_cipher_parameters, cipher_parameters&& server_cipher_parameters)
{
    assert(!pending_encrypt_cipher_ && !pending_decrypt_cipher_);
    pending_encrypt_cipher_ = make_cipher(client_cipher_parameters);
    pending_decrypt_cipher_ = make_cipher(server_cipher_parameters);
}

void tls_base::send_change_cipher_spec(const done_handler& handler)
{
    do_wrapped([&] {
        std::cout << "Sending change cipher spec." << std::endl;
        if (!pending_encrypt_cipher_) {
            FUNTLS_CHECK_FAILURE("Sending ChangeCipherSpec without a pending cipher suite");
        }
        change_cipher_spec msg{};
        std::vector<uint8_t> payload_buffer;
        append_to_buffer(payload_buffer, msg);
        //
        // Immediately after sending [the ChangeCipherSpec] message, the sender MUST instruct the
        // record layer to make the write pending state the write active state.
        //
        send_record(msg.content_type, payload_buffer, wrapped([this, handler] () {
                send_finished(handler);
            }, handler));
    }, handler);
}

void tls_base::read_change_cipher_spec(const done_handler& handler)
{
    recv_record(wrapped([this, handler] (record&& record) {
            FUNTLS_CHECK_BINARY(record.type,            ==, content_type::change_cipher_spec, "Invalid content type");
            FUNTLS_CHECK_BINARY(record.fragment.size(), ==, 1, "Invalid ChangeCipherSpec fragment size");
            FUNTLS_CHECK_BINARY(record.fragment[0],     !=, 0, "Invalid ChangeCipherSpec fragment data");
            //
            // Reception of [the ChangeCipherSpec] message causes the receiver to instruct the record layer to
            // immediately copy the read pending state into the read current state.
            //
            if (!pending_decrypt_cipher_) {
                FUNTLS_CHECK_FAILURE("Got ChangeCipherSpec without a pending cipher suite");
            }
            decrypt_cipher_          = std::move(pending_decrypt_cipher_);
            decrypt_sequence_number_ = 0;

            do_read_finished(handler);
        }, handler));
}

void tls_base::do_read_finished(const done_handler& handler)
{
    // Read finished
    read_handshake(wrapped([this, handler] (handshake&& handshake) {
            auto finished = tls::get_as<tls::finished>(handshake);
            const auto calced_verify_data = do_verify_data(connection_end_ == connection_end::server ? connection_end::client : connection_end::server);
            if (finished.verify_data != calced_verify_data) {
                std::ostringstream oss;
                oss << "Got invalid finished message. verify_data check failed. Expected ";
                oss << "'" << util::base16_encode(calced_verify_data) << "' Got";
                oss << "'" << util::base16_encode(finished.verify_data);
                FUNTLS_CHECK_FAILURE(oss.str());
            }
            handler(util::async_result<void>{});
        }, handler));
}

void tls_base::collapse_pending()
{
    append_to_buffer(handshake_messages_, pending_handshake_messages_);
    pending_handshake_messages_.clear();
}

void tls_base::do_recv_record_content(const recv_record_handler& handler)
{
    do_wrapped([&] {
        util::buffer_view     buf_view{&recv_buffer_[0], recv_buffer_.size()};
        content_type          content_type;
        protocol_version      protocol_version;
        uint16                length;
        from_bytes(content_type, buf_view);
        from_bytes(protocol_version, buf_view);
        from_bytes(length, buf_view);
        assert(buf_view.remaining() == 0);

        FUNTLS_CHECK_BINARY(protocol_version, ==, current_protocol_version(), "Wrong TLS version");
        FUNTLS_CHECK_BINARY(length, >=, 1, "Illegal fragment size");
        FUNTLS_CHECK_BINARY(length, <=, record::max_ciphertext_length, "Illegal fragment size");

        recv_buffer_.resize(length);
        assert(recv_buffer_.size() <= record::max_ciphertext_length);
        stream_->read(recv_buffer_,
                wrapped([this, content_type, protocol_version, handler]() {
                    do_decrypt(content_type, protocol_version, handler);
                }, handler));
    }, handler);
}

void tls_base::do_decrypt(tls::content_type content_type, tls::protocol_version protocol_version, const recv_record_handler& handler)
{
    do_wrapped([&] {
        //
        // Decrypt
        //
        const auto ver_buffer = verification_buffer(decrypt_sequence_number_++, content_type, current_protocol_version(), 0 /* filled in later */);
        recv_buffer_ = decrypt_cipher_->process(recv_buffer_, ver_buffer);

        // Decompression would happen here
        FUNTLS_CHECK_BINARY(recv_buffer_.size(), <=, record::max_compressed_length, "Illegal decoded fragment size");

        //
        // We now have a TLSPlaintext buffer for consumption
        //
        FUNTLS_CHECK_BINARY(recv_buffer_.size(), <=, record::max_plaintext_length, "Illegal decoded fragment size");

        if (content_type == tls::content_type::alert) {
            util::buffer_view alert_buf(&recv_buffer_[0], recv_buffer_.size());
            alert alert;
            from_bytes(alert, alert_buf);
            FUNTLS_CHECK_BINARY(alert_buf.remaining(), ==, 0, "Invalid alert message");

            std::ostringstream oss;
            oss << alert.level << " " << alert.description;
            std::cout << "Got alert: " << oss.str() <<  std::endl;
            throw std::runtime_error("Alert received: " + oss.str());
        }

        if (content_type == tls::content_type::handshake) {
            assert(pending_handshake_messages_.empty());
            pending_handshake_messages_ = recv_buffer_; // Will not become actove after this message has been parsed. This is a HACK
        }

        handler(record{content_type, protocol_version, std::move(recv_buffer_)});
    }, handler);
}

void tls_base::send_finished(const done_handler& handler)
{
    assert(encrypt_cipher_);
    encrypt_cipher_ = std::move(pending_encrypt_cipher_);
    //
    // The sequence number MUST be set to zero whenever a connection state is made the
    // active state.
    //
    encrypt_sequence_number_ = 0;
    //
    // A Finished message is always sent immediately after a change
    // cipher spec message to verify that the key exchange and
    // authentication processes were successful
    //
    send_handshake(tls::make_handshake(tls::finished{do_verify_data(connection_end_)}), handler);
}

} } // namespace funtls::tls
