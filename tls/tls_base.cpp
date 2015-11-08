#include <tls/tls_base.h>
#include <tls/tls_ser.h>
#include <util/test.h>
#include <util/base_conversion.h>

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
            auto frag = record.fragment.as_vector();
            handler(std::move(frag));
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
        const auto ver_buffer = verification_buffer(encrypt_sequence_number_++, content_type, current_protocol_version_, static_cast<uint16_t>(plaintext.size()));
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
            const auto& frag = record.fragment.as_vector();
            util::buffer_view frag_buf{frag.data(), frag.size()};
            handshake handshake;
            from_bytes(handshake, frag_buf);
            if (frag_buf.remaining()) {
                std::vector<uint8_t> excess(frag_buf.remaining());
                frag_buf.read(&excess[0], excess.size());
                FUNTLS_CHECK_FAILURE("Unread handshake data. Excess: " + util::base16_encode(excess));
            }
            handler(std::move(handshake));
        }, handler));
}

void tls_base::set_pending_ciphers(const std::vector<uint8_t>& pre_master_secret)
{
    // We can now compute the master_secret as specified in rfc5246 8.1
    // master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]

    const auto cipher_param = current_cipher_parameters();
    std::vector<uint8_t> rand_buf;
    append_to_buffer(rand_buf, client_random());
    append_to_buffer(rand_buf, server_random());
    master_secret(PRF(cipher_param.prf_algorithm, pre_master_secret, "master secret", rand_buf, master_secret_size));
    //std::cout << "Master secret: " << util::base16_encode(master_secret) << std::endl;

    // Now do Key Calculation http://tools.ietf.org/html/rfc5246#section-6.3
    // key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random)
    const size_t key_block_length  = 2 * cipher_param.mac_key_length + 2 * cipher_param.key_length + 2 * cipher_param.fixed_iv_length;
    std::vector<uint8_t> randbuf;
    append_to_buffer(randbuf, server_random());
    append_to_buffer(randbuf, client_random());
    auto key_block = PRF(cipher_param.prf_algorithm, master_secret(), "key expansion", randbuf, key_block_length);

    //std::cout << "Keyblock:\n" << util::base16_encode(key_block) << "\n";

    auto kbi = key_block.begin();
    auto client_mac_key = std::vector<uint8_t>{kbi, kbi+cipher_param.mac_key_length};  kbi += cipher_param.mac_key_length;
    auto server_mac_key = std::vector<uint8_t>{kbi, kbi+cipher_param.mac_key_length};  kbi += cipher_param.mac_key_length;
    auto client_enc_key = std::vector<uint8_t>{kbi, kbi+cipher_param.key_length};      kbi += cipher_param.key_length;
    auto server_enc_key = std::vector<uint8_t>{kbi, kbi+cipher_param.key_length};      kbi += cipher_param.key_length;
    auto client_iv      = std::vector<uint8_t>{kbi, kbi+cipher_param.fixed_iv_length}; kbi += cipher_param.fixed_iv_length;
    auto server_iv      = std::vector<uint8_t>{kbi, kbi+cipher_param.fixed_iv_length}; kbi += cipher_param.fixed_iv_length;
    assert(kbi == key_block.end());

    if (connection_end_ == connection_end::client) {
        pending_encrypt_cipher_ = make_cipher(cipher_parameters{cipher_parameters::encrypt, cipher_param, client_mac_key, client_enc_key, client_iv});
        pending_decrypt_cipher_ = make_cipher(cipher_parameters{cipher_parameters::decrypt, cipher_param, server_mac_key, server_enc_key, server_iv});
    } else {
        pending_encrypt_cipher_ = make_cipher(cipher_parameters{cipher_parameters::encrypt, cipher_param, server_mac_key, server_enc_key, server_iv});
        pending_decrypt_cipher_ = make_cipher(cipher_parameters{cipher_parameters::decrypt, cipher_param, client_mac_key, client_enc_key, client_iv});
    }
}

void tls_base::send_change_cipher_spec(const done_handler& handler)
{
    do_wrapped([&] {
        //std::cout << "Sending change cipher spec." << std::endl;
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
            //std::cout << "Got alert: " << oss.str() <<  std::endl;
            throw std::runtime_error("Alert received: " + oss.str());
        }

        bool check_version = true;

        if (content_type == tls::content_type::handshake) {
            assert(pending_handshake_messages_.empty());
            pending_handshake_messages_ = recv_buffer_; // Will not become actove after this message has been parsed. This is a HACK

            //
            // The client hello message is allowed to newer than the current version
            // (which at the start is the lowest possible version)
            //
            if (recv_buffer_.size() > 1 && recv_buffer_[0] == static_cast<uint8_t>(handshake_type::client_hello)) {
                FUNTLS_CHECK_BINARY(protocol_version.major, ==, current_protocol_version().major, "Invalid TLS version");
                FUNTLS_CHECK_BINARY(protocol_version.minor, >=, current_protocol_version().minor, "Invalid TLS version");
                FUNTLS_CHECK_BINARY(protocol_version.minor, <=, protocol_version_tls_1_2.minor, "Invalid TLS version");
                check_version = false;
            }
        }

        if (check_version) {
            FUNTLS_CHECK_BINARY(protocol_version, ==, current_protocol_version(), "Wrong TLS version");
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

std::vector<uint8_t> tls_base::do_verify_data(tls_base::connection_end ce) const
{
    // verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1]
    // finished_label: 
    //      For Finished messages sent by the client, the string "client finished".
    //      For Finished messages sent by the server, the string "server finished".
    // handshake_messages:
    //      All of the data from all messages in this handshake (not
    //      including any HelloRequest messages) up to, but not including,
    //      this message
    const auto prf_algo       = current_cipher_parameters().prf_algorithm;
    const auto finished_label = ce == tls_base::connection_end::server ? "server finished" : "client finished";

    std::vector<uint8_t> handshake_digest;
    if (prf_algo == prf_algorithm::sha256) {
        handshake_digest = hash::sha256{}.input(handshake_messages()).result();
    } else if (prf_algo == prf_algorithm::sha384) {
         handshake_digest = hash::sha384{}.input(handshake_messages()).result();
    } else {
        std::ostringstream msg;
        msg << "Unsupported PRF algorithm " << prf_algo;
        FUNTLS_CHECK_FAILURE(msg.str());
    }
    return PRF(prf_algo, master_secret(), finished_label, handshake_digest, finished::verify_data_min_length);
}

} } // namespace funtls::tls
