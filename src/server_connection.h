#pragma once

#include "common/tunnel_protocol.h"
#include "common/tls_wrapper.h"
#include "server_shared.h"

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include <cstddef>
#include <cstdint>
#include <deque>
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
    struct RequestState {
        enum class ResponseMode { None, StaticBody, EventStream };
        std::string method;
        std::string path;
        std::map<std::string, std::string> headers;
        std::vector<std::uint8_t> body;
        ResponseMode response_mode = ResponseMode::None;
        std::vector<std::uint8_t> response_body;
        std::size_t response_offset = 0;
        bool response_started = false;
    };

    enum class Mode { Handshaking, Http1, Http2, Closed };

    enum class UpstreamState {
        Connecting,
        ProxyMethodWrite,
        ProxyMethodRead,
        ProxyConnectWrite,
        ProxyConnectReadHead,
        ProxyConnectReadDomainLength,
        ProxyConnectReadBody,
        Open
    };

    struct DownlinkFrame {
        proxy::FrameType type = proxy::FrameType::Data;
        std::uint32_t stream_id = 0;
        std::vector<std::uint8_t> encoded;
        std::size_t offset = 0;
    };

    struct UpstreamStream {
        std::uint32_t id = 0;
        proxy::socket_t sock = proxy::kInvalidSocket;
        UpstreamState state = UpstreamState::Connecting;
        std::uint8_t requested_atyp = 0;
        std::string requested_host;
        std::uint16_t requested_port = 0;
        bool use_socks5 = false;
        std::vector<std::uint8_t> pending_uplink;
        std::size_t pending_uplink_offset = 0;
        std::vector<std::uint8_t> control_out;
        std::size_t control_out_offset = 0;
        std::vector<std::uint8_t> control_in;
        std::size_t control_expected = 0;
    };

    bool client_wants_read() const;
    bool client_wants_write() const;
    bool has_pending_tls_output() const;
    proxy::EventFlags upstream_interest(const UpstreamStream& stream) const;
    void note_tls_status(proxy::TlsSocket::IoStatus status);
    void drive_tls_handshake();
    bool initialize_http2();
    bool queue_session_output(std::size_t budget_bytes = static_cast<std::size_t>(-1));
    void prepare_http2_output();
    void flush_tls_output();
    void read_http1_request();
    void read_http2_frames();
    void start_upstream_connect(std::uint32_t stream_id, std::uint8_t atyp,
                                const std::string& requested_host, std::uint16_t requested_port);
    bool finish_nonblocking_connect(UpstreamStream& stream);
    bool process_upstream_write(UpstreamStream& stream);
    bool process_socks5_read(UpstreamStream& stream);
    bool process_upstream_read(UpstreamStream& stream);
    bool has_pending_downlink_data() const;
    DownlinkFrame* current_downlink_data_frame();
    void enqueue_downlink(proxy::FrameType type, std::uint32_t stream_id,
                          const std::vector<std::uint8_t>& payload);
    void purge_downlink_data_for_stream(std::uint32_t stream_id);
    void close_logical_stream(std::uint32_t stream_id, bool notify_client);
    void close_all_upstreams();
    void close_connection();
    std::string get_header_value_ci(const RequestState& request, const std::string& name) const;
    bool is_authorized(const RequestState& request) const;
    void submit_static_response(int32_t stream_id, int status, const std::string& content_type,
                                const std::vector<std::uint8_t>& body);
    void handle_request(int32_t stream_id);
    void handle_upload_frames(RequestState& request);

    static nghttp2_ssize read_response_body(nghttp2_session*, int32_t, uint8_t* buf, size_t length,
                                            uint32_t* data_flags, nghttp2_data_source* source, void* user_data);
    static int on_begin_headers(nghttp2_session*, const nghttp2_frame* frame, void* user_data);
    static int on_header(nghttp2_session*, const nghttp2_frame* frame, const uint8_t* name, size_t namelen,
                         const uint8_t* value, size_t valuelen, uint8_t, void* user_data);
    static int on_data_chunk_recv(nghttp2_session*, uint8_t, int32_t stream_id, const uint8_t* data, size_t len,
                                  void* user_data);
    static int on_frame_recv(nghttp2_session*, const nghttp2_frame* frame, void* user_data);
    static int on_stream_close(nghttp2_session*, int32_t stream_id, uint32_t, void* user_data);
    static nghttp2_ssize select_padding(nghttp2_session*, const nghttp2_frame* frame, size_t max_payloadlen, void*);

    proxy::socket_t accepted_socket_ = proxy::kInvalidSocket;
    ServerConfig config_;
    proxy::TlsSocket tls_;
    nghttp2_session* h2_ = nullptr;
    std::map<int32_t, RequestState> requests_;
    std::map<std::uint32_t, UpstreamStream> streams_;
    std::deque<DownlinkFrame> downlink_control_;
    std::map<std::uint32_t, std::deque<DownlinkFrame>> downlink_data_by_stream_;
    std::deque<std::uint32_t> downlink_data_round_robin_;
    std::vector<std::uint8_t> tls_out_;
    std::size_t tls_out_offset_ = 0;
    std::string http1_in_;
    int32_t event_stream_id_ = -1;
    Mode mode_;
    bool http1_response_started_ = false;
    bool tunnel_opened_ = false;
    bool shutdown_requested_ = false;
    bool tls_need_read_ = false;
    bool tls_need_write_ = false;
};
