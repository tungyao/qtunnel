#pragma once

#include "common/tls_wrapper.h"
#include "http2_session_driver.h"
#include "server_shared.h"
#include "upstream_peer.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

class ServerConnection {
public:
    ServerConnection(proxy::socket_t accepted_socket, ServerConfig config);
    ~ServerConnection();

    ServerConnection(const ServerConnection&) = delete;
    ServerConnection& operator=(const ServerConnection&) = delete;

    bool start();
    bool closed() const;
    proxy::socket_t client_socket() const;

    void collect_watches(std::map<proxy::socket_t, proxy::EventFlags>& desired,
                         std::map<proxy::socket_t, SocketBinding>& bindings);
    void on_client_event(bool readable, bool writable, bool error, bool hangup);
    void on_upstream_event(std::uint32_t stream_id, bool readable, bool writable, bool error, bool hangup);

private:
    enum class Mode { Handshaking, Http1, Http2, Closed };

    bool client_wants_read() const;
    bool client_wants_write() const;
    bool has_pending_tls_output() const;
    void note_tls_status(proxy::TlsSocket::IoStatus status);
    void drive_tls_handshake();
    void flush_tls_output();
    void read_http1_request();
    void read_http2_frames();
    void start_upstream_connect(std::uint32_t stream_id, std::uint8_t atyp,
                                const std::string& requested_host, std::uint16_t requested_port);
    void enqueue_downlink(proxy::FrameType type, std::uint32_t stream_id, const std::vector<std::uint8_t>& payload);
    void handle_tunnel_stream_data(std::uint32_t stream_id, const std::vector<std::uint8_t>& payload);
    void close_logical_stream(std::uint32_t stream_id, bool notify_client);
    void close_all_upstreams();
    void close_connection();

    proxy::socket_t accepted_socket_ = proxy::kInvalidSocket;
    ServerConfig config_;
    proxy::TlsSocket tls_;
    Http2SessionDriver h2_driver_;
    std::map<std::uint32_t, server_upstream::Peer> streams_;
    std::vector<std::uint8_t> tls_out_;
    std::size_t tls_out_offset_ = 0;
    std::string http1_in_;
    Mode mode_;
    bool http1_response_started_ = false;
    bool tls_need_read_ = false;
    bool tls_need_write_ = false;
};
