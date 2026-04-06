#pragma once

#include "server_shared.h"
#include "upstream_peer.h"

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

enum class SendResult { Ok, WouldBlock, Error };

class Http2SessionDriver {
public:
    struct Callbacks {
        // CONNECT request received and authorized: start upstream connection
        std::function<void(int32_t h2_stream_id,
                           const std::string& host,
                           uint16_t port)> on_connect;

        // Client sent DATA on a stream (uplink). Do NOT call nghttp2_session_consume.
        // The caller must call consume_stream_window() after writing to upstream.
        std::function<void(int32_t h2_stream_id,
                           const uint8_t* data,
                           std::size_t len)> on_upload_data;

        // H2 stream closed by client (RST_STREAM or END_STREAM)
        std::function<void(int32_t h2_stream_id)> on_stream_close;
    };

    Http2SessionDriver(ServerConfig config, Callbacks callbacks);
    ~Http2SessionDriver();

    Http2SessionDriver(const Http2SessionDriver&) = delete;
    Http2SessionDriver& operator=(const Http2SessionDriver&) = delete;

    using SendFn = std::function<SendResult(const uint8_t* data,
                                            std::size_t len,
                                            std::size_t& wrote)>;
    using PeerLookup = std::function<server_upstream::Peer*(int32_t h2_stream_id)>;

    void set_send_fn(SendFn fn)         { send_fn_ = std::move(fn); }
    void set_peer_lookup(PeerLookup fn) { peer_lookup_ = std::move(fn); }

    bool initialize();
    bool receive(const uint8_t* data, std::size_t len);

    // Drive session send. Returns false on fatal protocol error.
    bool session_send();

    // Called by ServerConnection when upstream connects successfully
    void notify_upstream_connected(int32_t h2_stream_id);

    // Called by ServerConnection when upstream connection fails
    void notify_upstream_failed(int32_t h2_stream_id, const std::string& error);

    // Called by ServerConnection after upstream provides new data
    void notify_upstream_data(int32_t h2_stream_id);

    // Called by ServerConnection when upstream closes
    void notify_upstream_eof(int32_t h2_stream_id);

    // Called after successfully writing N bytes to upstream.
    // Releases the H2 stream receive window by N bytes -> sends WINDOW_UPDATE to client.
    void consume_stream_window(int32_t h2_stream_id, std::size_t n);

    bool shutdown_requested() const { return shutdown_requested_; }
    nghttp2_session* session() const { return session_; }

private:
    struct StreamState {
        std::string method;
        std::string authority;   // host:port for CONNECT
        std::map<std::string, std::string> headers;
        bool response_started = false;
        // For static responses (non-tunnel streams)
        std::string static_body;
        std::size_t static_body_offset = 0;
    };

    void handle_connect(int32_t stream_id);
    void serve_static(int32_t stream_id, int status,
                      const std::string& content_type,
                      const std::string& body);

    static bool parse_authority(const std::string& authority,
                                std::string& host, uint16_t& port);

    // nghttp2 callbacks
    static nghttp2_ssize send_callback(nghttp2_session*, const uint8_t* data,
                                       std::size_t length, int, void* user_data);
    static nghttp2_ssize per_stream_read_callback(nghttp2_session*, int32_t stream_id,
                                                   uint8_t* buf, std::size_t length,
                                                   uint32_t* data_flags,
                                                   nghttp2_data_source* source,
                                                   void* user_data);
    static nghttp2_ssize static_body_read_callback(nghttp2_session*, int32_t stream_id,
                                                    uint8_t* buf, std::size_t length,
                                                    uint32_t* data_flags,
                                                    nghttp2_data_source* source,
                                                    void* user_data);
    static int on_begin_headers(nghttp2_session*, const nghttp2_frame*, void*);
    static int on_header(nghttp2_session*, const nghttp2_frame*,
                         const uint8_t* name, std::size_t namelen,
                         const uint8_t* value, std::size_t valuelen,
                         uint8_t, void*);
    static int on_data_chunk_recv(nghttp2_session*, uint8_t,
                                  int32_t stream_id,
                                  const uint8_t* data, std::size_t len, void*);
    static int on_frame_recv(nghttp2_session*, const nghttp2_frame*, void*);
    static int on_stream_close(nghttp2_session*, int32_t stream_id, uint32_t, void*);
    static int on_invalid_frame_recv(nghttp2_session*, const nghttp2_frame*,
                                      int error_code, void*);
    static nghttp2_ssize select_padding(nghttp2_session*, const nghttp2_frame*,
                                        std::size_t max_payloadlen, void*);

    ServerConfig config_;
    Callbacks    callbacks_;
    nghttp2_session* session_ = nullptr;
    std::map<int32_t, StreamState> streams_;

    SendFn      send_fn_;
    PeerLookup  peer_lookup_;

    bool shutdown_requested_ = false;
};
