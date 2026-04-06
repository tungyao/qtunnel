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
    ServerConnection(proxy::socket_t accepted_socket,
                     ServerConfig config,
                     RuntimeHooks hooks,
                     std::uint64_t conn_id,
                     std::string client_addr);
    ~ServerConnection();

    ServerConnection(const ServerConnection&) = delete;
    ServerConnection& operator=(const ServerConnection&) = delete;

    bool start();
    bool closed() const { return mode_ == Mode::Closed; }
    proxy::socket_t client_fd() const { return tls_.raw_socket(); }

    // Called by ServerRuntime on epoll events
    void on_client_event(bool readable, bool writable);
    void on_upstream_event(int32_t h2_stream_id, bool readable, bool writable);

    // Called by ServerRuntime after all I/O events each loop iteration
    void drive_session_send();
    void rearm_all_upstreams();

private:
    enum class Mode { Handshaking, Http1, Http2, Closed };

    // TLS handshake
    void drive_tls_handshake();

    // HTTP/1 fallback (static page only)
    void read_http1_request();
    void flush_http1_response();

    // HTTP/2
    void read_h2_frames();

    // Called by Http2SessionDriver callbacks
    void on_connect_request(int32_t h2_stream_id,
                             const std::string& host, uint16_t port);
    void on_upload_data(int32_t h2_stream_id,
                         const uint8_t* data, std::size_t len);
    void on_h2_stream_close(int32_t h2_stream_id);

    // Upstream lifecycle
    void close_stream_only(int32_t h2_stream_id);
    void close_all_upstreams();
    void close_connection();
    void rearm_upstream(int32_t h2_stream_id, const server_upstream::Peer& peer);

    // TLS write: used as send_fn_ injected into Http2SessionDriver
    SendResult tls_send(const uint8_t* data, std::size_t len, std::size_t& wrote);

    proxy::socket_t  accepted_socket_ = proxy::kInvalidSocket;
    ServerConfig     config_;
    RuntimeHooks     hooks_;
    proxy::TlsSocket tls_;
    Http2SessionDriver h2_driver_;
    std::uint64_t    conn_id_ = 0;
    std::string      client_addr_;

    std::map<int32_t, server_upstream::Peer> streams_;

    // HTTP/1 state (for non-H2 clients, serve static page only)
    std::string http1_in_;
    std::vector<uint8_t> http1_out_;
    std::size_t http1_out_offset_ = 0;
    bool http1_response_started_ = false;

    // TLS write state
    bool tls_need_write_ = false;
    bool tls_need_read_  = false;

    Mode mode_ = Mode::Closed;
};
