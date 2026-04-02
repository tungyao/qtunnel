#pragma once

#include "common/tunnel_protocol.h"
#include "server_shared.h"

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <vector>

class Http2SessionDriver {
public:
    struct Callbacks {
        std::function<void(std::uint32_t, std::uint8_t, const std::string&, std::uint16_t)> on_open_stream;
        std::function<void(std::uint32_t, const std::vector<std::uint8_t>&)> on_stream_data;
        std::function<void(std::uint32_t)> on_stream_close;
        std::function<void()> on_close_all_upstreams;
    };

    Http2SessionDriver(ServerConfig config, Callbacks callbacks);
    ~Http2SessionDriver();

    Http2SessionDriver(const Http2SessionDriver&) = delete;
    Http2SessionDriver& operator=(const Http2SessionDriver&) = delete;

    bool initialize(std::vector<std::uint8_t>& tls_out);
    bool receive(const std::uint8_t* data, std::size_t len, std::vector<std::uint8_t>& tls_out);
    bool prepare_output(std::vector<std::uint8_t>& tls_out, std::size_t budget_bytes);

    void enqueue_downlink(proxy::FrameType type, std::uint32_t stream_id, const std::vector<std::uint8_t>& payload,
                          std::vector<std::uint8_t>& tls_out, std::size_t budget_bytes);
    void purge_downlink_data_for_stream(std::uint32_t stream_id);

    int32_t event_stream_id() const;
    bool shutdown_requested() const;

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

    struct DownlinkFrame {
        proxy::FrameType type = proxy::FrameType::Data;
        std::uint32_t stream_id = 0;
        std::vector<std::uint8_t> encoded;
        std::size_t offset = 0;
    };

    bool queue_session_output(std::size_t budget_bytes = static_cast<std::size_t>(-1));
    void drain_tls_output(std::vector<std::uint8_t>& tls_out);
    bool has_pending_downlink_data() const;
    DownlinkFrame* current_downlink_data_frame();
    std::string get_header_value_ci(const RequestState& request, const std::string& name) const;
    bool is_authorized(const RequestState& request) const;
    void submit_static_response(int32_t stream_id, int status, const std::string& content_type,
                                const std::vector<std::uint8_t>& body, std::vector<std::uint8_t>& tls_out);
    void handle_request(int32_t stream_id, std::vector<std::uint8_t>& tls_out);
    void handle_upload_frames(RequestState& request, std::vector<std::uint8_t>& tls_out);

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

    ServerConfig config_;
    Callbacks callbacks_;
    nghttp2_session* session_ = nullptr;
    std::map<int32_t, RequestState> requests_;
    std::deque<DownlinkFrame> downlink_control_;
    std::map<std::uint32_t, std::deque<DownlinkFrame>> downlink_data_by_stream_;
    std::deque<std::uint32_t> downlink_data_round_robin_;
    std::vector<std::uint8_t> pending_tls_out_;
    int32_t event_stream_id_ = -1;
    bool tunnel_opened_ = false;
    bool shutdown_requested_ = false;
};
