#include "http2_session_driver.h"
#include "homepage_html.h"

#include "common/logging.h"
#include "common/tunnel_protocol.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

#ifdef _WIN32
#else
#include <strings.h>
#endif

namespace {

constexpr int32_t  kHttp2WindowSize   = 16 * 1024 * 1024;
constexpr uint32_t kHttp2MaxFrameSize = 1024 * 1024;

using proxy::select_http2_padded_length;

nghttp2_nv make_nv(const std::string& n, const std::string& v) {
    nghttp2_nv nv{};
    nv.name     = reinterpret_cast<uint8_t*>(const_cast<char*>(n.data()));
    nv.value    = reinterpret_cast<uint8_t*>(const_cast<char*>(v.data()));
    nv.namelen  = n.size();
    nv.valuelen = v.size();
    nv.flags    = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

int ascii_casecmp(const char* lhs, const char* rhs) {
#ifdef _WIN32
    return _stricmp(lhs, rhs);
#else
    return strcasecmp(lhs, rhs);
#endif
}

} // namespace

Http2SessionDriver::Http2SessionDriver(ServerConfig config, Callbacks callbacks)
    : config_(std::move(config)), callbacks_(std::move(callbacks)) {}

Http2SessionDriver::~Http2SessionDriver() {
    if (session_ != nullptr) nghttp2_session_del(session_);
}

bool Http2SessionDriver::initialize() {
    nghttp2_session_callbacks* cbs = nullptr;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback2(cbs, &Http2SessionDriver::send_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, &Http2SessionDriver::on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cbs, &Http2SessionDriver::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, &Http2SessionDriver::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, &Http2SessionDriver::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, &Http2SessionDriver::on_stream_close);
    nghttp2_session_callbacks_set_select_padding_callback2(cbs, &Http2SessionDriver::select_padding);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(cbs, &Http2SessionDriver::on_invalid_frame_recv);

    nghttp2_option* option = nullptr;
    nghttp2_option_new(&option);
    nghttp2_option_set_no_auto_window_update(option, 1);

    const int rv = nghttp2_session_server_new2(&session_, cbs, this, option);
    nghttp2_session_callbacks_del(cbs);
    nghttp2_option_del(option);
    if (rv != 0) {
        PROXY_LOG(Error, "[h2] nghttp2_session_server_new2 failed: " << rv);
        return false;
    }

    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, static_cast<uint32_t>(kHttp2WindowSize)},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE,       kHttp2MaxFrameSize},
    };
    if (nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, settings, 2) != 0) {
        PROXY_LOG(Error, "[h2] nghttp2_submit_settings failed");
        return false;
    }
    if (nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, 0,
                                              kHttp2WindowSize) != 0) {
        PROXY_LOG(Error, "[h2] nghttp2_session_set_local_window_size failed");
        return false;
    }

    PROXY_LOG(Info, "[h2] session initialized, sending SETTINGS");
    return session_send();
}

bool Http2SessionDriver::receive(const uint8_t* data, std::size_t len) {
    ERR_clear_error();
    const auto consumed = nghttp2_session_mem_recv2(session_, data, len);
    if (consumed < 0) {
        const int err = static_cast<int>(consumed);
        PROXY_LOG(Error, "[h2] nghttp2_session_mem_recv2 failed: " << err
                      << " (" << nghttp2_strerror(err) << ")");
        unsigned long ssl_err = ERR_get_error();
        if (ssl_err != 0) {
            char buf[256];
            ERR_error_string_n(ssl_err, buf, sizeof(buf));
            PROXY_LOG(Error, "[h2] OpenSSL error: " << buf);
        }
        return false;
    }
    return true;
}

bool Http2SessionDriver::session_send() {
    const int ret = nghttp2_session_send(session_);
    if (ret == NGHTTP2_ERR_WOULDBLOCK) {
        return true;
    }
    if (ret != 0) {
        PROXY_LOG(Error, "[h2] session_send failed: " << ret);
        return false;
    }
    return true;
}

void Http2SessionDriver::notify_upstream_connected(int32_t h2_stream_id) {
    auto it = streams_.find(h2_stream_id);
    if (it == streams_.end()) return;
    it->second.response_started = true;

    // Send :status 200 (no END_STREAM - data follows)
    // Use static strings to ensure lifetime
    static const char* const_status = ":status";
    static const char* const_200 = "200";

    nghttp2_nv nv{};
    nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(const_status));
    nv.namelen = 7;
    nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(const_200));
    nv.valuelen = 3;
    nv.flags = NGHTTP2_NV_FLAG_NONE;

    nghttp2_data_provider2 provider{};
    provider.source.ptr    = reinterpret_cast<void*>(static_cast<intptr_t>(h2_stream_id));
    provider.read_callback = &Http2SessionDriver::per_stream_read_callback;

    nghttp2_submit_response2(session_, h2_stream_id, &nv, 1, &provider);
}

void Http2SessionDriver::notify_upstream_failed(int32_t h2_stream_id,
                                                 const std::string& /*error*/) {
    serve_static(h2_stream_id, 502, "text/plain", "bad gateway");
    streams_.erase(h2_stream_id);
}

void Http2SessionDriver::notify_upstream_data(int32_t h2_stream_id) {
    auto it = streams_.find(h2_stream_id);
    if (it == streams_.end()) return;
    // Resume the deferred data provider for this stream
    nghttp2_session_resume_data(session_, h2_stream_id);
}

void Http2SessionDriver::notify_upstream_eof(int32_t h2_stream_id) {
    // The Peer already has upstream_eof = true.
    // Resume so the data_provider can drain remaining data and then send END_STREAM.
    nghttp2_session_resume_data(session_, h2_stream_id);
}

void Http2SessionDriver::consume_stream_window(int32_t h2_stream_id, std::size_t n) {
    // Release the stream-level H2 receive window.
    nghttp2_session_consume_stream(session_, h2_stream_id, static_cast<std::size_t>(n));
    // Also consume connection-level window so other streams aren't blocked
    nghttp2_session_consume_connection(session_, static_cast<std::size_t>(n));
}

// static
nghttp2_ssize Http2SessionDriver::send_callback(nghttp2_session*,
                                                 const uint8_t* data,
                                                 std::size_t length,
                                                 int, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    if (!self->send_fn_) return NGHTTP2_ERR_CALLBACK_FAILURE;
    std::size_t wrote = 0;
    const SendResult result = self->send_fn_(data, length, wrote);
    if (result == SendResult::WouldBlock) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    if (result == SendResult::Error) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return static_cast<nghttp2_ssize>(wrote);
}

// static - called by nghttp2 to read downstream data for a CONNECT tunnel stream
nghttp2_ssize Http2SessionDriver::per_stream_read_callback(nghttp2_session*,
                                                            int32_t stream_id,
                                                            uint8_t* buf,
                                                            std::size_t length,
                                                            uint32_t* data_flags,
                                                            nghttp2_data_source*,
                                                            void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    if (!self->peer_lookup_) return NGHTTP2_ERR_CALLBACK_FAILURE;

    server_upstream::Peer* peer = self->peer_lookup_(stream_id);
    if (peer == nullptr) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }

    if (peer->pending_downlink.empty()) {
        if (peer->upstream_eof) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        peer->downlink_deferred = true;
        return NGHTTP2_ERR_DEFERRED;
    }

    const std::size_t n = peer->pending_downlink.consume(buf, length);

    // If ChunkQueue dropped below low water, re-enable upstream reads
    if (peer->pending_downlink.below_low_water()) {
        peer->downlink_deferred = false;
    }

    // If more data remains, schedule another call
    if (!peer->pending_downlink.empty()) {
        nghttp2_session_resume_data(self->session_, stream_id);
    }

    return static_cast<nghttp2_ssize>(n);
}

// static - called by nghttp2 to read static response body
nghttp2_ssize Http2SessionDriver::static_body_read_callback(nghttp2_session*,
                                                             int32_t stream_id,
                                                             uint8_t* buf,
                                                             std::size_t length,
                                                             uint32_t* data_flags,
                                                             nghttp2_data_source*,
                                                             void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    auto it = self->streams_.find(stream_id);
    if (it == self->streams_.end()) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    StreamState& st = it->second;
    const std::size_t remaining = st.static_body.size() - st.static_body_offset;
    const std::size_t n = (length < remaining) ? length : remaining;
    if (n > 0) {
        std::memcpy(buf, st.static_body.data() + st.static_body_offset, n);
        st.static_body_offset += n;
    }
    if (st.static_body_offset >= st.static_body.size()) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return static_cast<nghttp2_ssize>(n);
}

// static
int Http2SessionDriver::on_begin_headers(nghttp2_session*, const nghttp2_frame* frame,
                                          void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS) {
        PROXY_LOG(Info, "[h2] on_begin_headers stream=" << frame->hd.stream_id
                      << " cat=" << static_cast<int>(frame->headers.cat)
                      << " flags=" << static_cast<int>(frame->hd.flags)
                      << " length=" << frame->hd.length);
        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            self->streams_[frame->hd.stream_id] = StreamState{};
            PROXY_LOG(Info, "[h2] created StreamState for stream=" << frame->hd.stream_id);
        } else {
            PROXY_LOG(Info, "[h2] ignoring non-request HEADERS, cat=" 
                          << static_cast<int>(frame->headers.cat));
        }
    }
    return 0;
}

// static
int Http2SessionDriver::on_header(nghttp2_session*, const nghttp2_frame* frame,
                                   const uint8_t* name, std::size_t namelen,
                                   const uint8_t* value, std::size_t valuelen,
                                   uint8_t, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    auto it = self->streams_.find(frame->hd.stream_id);
    if (it == self->streams_.end()) {
        PROXY_LOG(Error, "[h2] on_header: stream " << frame->hd.stream_id << " not found");
        return 0;
    }
    const std::string hname(reinterpret_cast<const char*>(name), namelen);
    const std::string hvalue(reinterpret_cast<const char*>(value), valuelen);
    PROXY_LOG(Info, "[h2] on_header stream=" << frame->hd.stream_id
                  << " name=[" << hname << "] value=[" << hvalue << "]"
                  << " namelen=" << namelen << " valuelen=" << valuelen);
    if      (hname == ":method")    it->second.method    = hvalue;
    else if (hname == ":authority") it->second.authority = hvalue;
    else                            it->second.headers[hname] = hvalue;
    return 0;
}

// static
int Http2SessionDriver::on_data_chunk_recv(nghttp2_session*, uint8_t,
                                            int32_t stream_id,
                                            const uint8_t* data, std::size_t len,
                                            void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    // IMPORTANT: Do NOT call nghttp2_session_consume here.
    // consume_stream_window() will be called after bytes are written to upstream.
    if (self->callbacks_.on_upload_data)
        self->callbacks_.on_upload_data(stream_id, data, len);
    return 0;
}

// static
int Http2SessionDriver::on_frame_recv(nghttp2_session*, const nghttp2_frame* frame,
                                       void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS) {
        PROXY_LOG(Info, "[h2] HEADERS frame complete stream=" << frame->hd.stream_id
                      << " cat=" << static_cast<int>(frame->headers.cat));
        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            auto it = self->streams_.find(frame->hd.stream_id);
            if (it != self->streams_.end()) {
                PROXY_LOG(Info, "[h2] HEADERS complete: method=" << it->second.method
                              << " authority=" << it->second.authority
                              << " headers_count=" << it->second.headers.size());
            }
            self->handle_connect(static_cast<int32_t>(frame->hd.stream_id));
        }
    }
    return 0;
}

// static
int Http2SessionDriver::on_stream_close(nghttp2_session*, int32_t stream_id,
                                         uint32_t, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    self->streams_.erase(stream_id);
    if (self->callbacks_.on_stream_close)
        self->callbacks_.on_stream_close(stream_id);
    return 0;
}

// static
int Http2SessionDriver::on_invalid_frame_recv(nghttp2_session*, const nghttp2_frame* frame,
                                               int error_code, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    PROXY_LOG(Error, "[h2] on_invalid_frame_recv stream=" << frame->hd.stream_id
                  << " type=" << static_cast<int>(frame->hd.type)
                  << " error_code=" << error_code
                  << " (" << nghttp2_strerror(error_code) << ")");
    return 0;
}

// static
nghttp2_ssize Http2SessionDriver::select_padding(nghttp2_session*,
                                                  const nghttp2_frame* frame,
                                                  std::size_t max_payloadlen,
                                                  void*) {
    return static_cast<nghttp2_ssize>(
        select_http2_padded_length(frame->hd.type, frame->hd.length, max_payloadlen));
}

void Http2SessionDriver::handle_connect(int32_t stream_id) {
    PROXY_LOG(Info, "[h2] handle_connect stream=" << stream_id);
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        PROXY_LOG(Error, "[h2] stream not found");
        return;
    }
    StreamState& st = it->second;
    if (st.response_started) {
        PROXY_LOG(Debug, "[h2] response already started");
        return;
    }

    PROXY_LOG(Info, "[h2] stream=" << stream_id 
                  << " method=[" << st.method << "]"
                  << " authority=[" << st.authority << "]"
                  << " headers_count=" << st.headers.size());

    for (const auto& h : st.headers) {
        PROXY_LOG(Debug, "[h2] header: " << h.first << " = " << h.second);
    }

    if (!config_.auth_password.empty()) {
        const auto auth_it = st.headers.find("x-tunnel-auth");
        const bool auth_ok = (auth_it != st.headers.end() &&
                               auth_it->second == config_.auth_password);
        if (!auth_ok) {
            PROXY_LOG(Error, "[h2] stream=" << stream_id << " auth failed");
            serve_static(stream_id, 403, "text/plain", "forbidden");
            return;
        }
    }

    if (st.method == "GET") {
        PROXY_LOG(Info, "[h2] stream=" << stream_id << " GET request");
        const std::string body = generated::kHomepageHtml;
        serve_static(stream_id, 200, "text/html; charset=utf-8", body);
        return;
    }

    std::string host;
    uint16_t port = 0;
    
    if (st.method == "CONNECT" && !st.authority.empty()) {
        if (!parse_authority(st.authority, host, port)) {
            PROXY_LOG(Error, "[h2] stream=" << stream_id << " bad authority: " << st.authority);
            serve_static(stream_id, 400, "text/plain", "bad authority");
            return;
        }
    } else {
        auto alt_it = st.headers.find("x-tunnel-a");
        if (alt_it != st.headers.end()) {
            PROXY_LOG(Info, "[h2] stream=" << stream_id << " using x-tunnel-a as authority");
            if (!parse_authority(alt_it->second, host, port)) {
                PROXY_LOG(Error, "[h2] stream=" << stream_id << " bad x-tunnel-a: " << alt_it->second);
                serve_static(stream_id, 400, "text/plain", "bad authority");
                return;
            }
        } else {
            PROXY_LOG(Error, "[h2] stream=" << stream_id 
                          << " no CONNECT authority or x-tunnel-a, method=" << st.method);
            serve_static(stream_id, 400, "text/plain", "missing authority");
            return;
        }
    }

    PROXY_LOG(Info, "[h2] stream=" << stream_id << " CONNECT " << host << ":" << port);
    if (callbacks_.on_connect)
        callbacks_.on_connect(stream_id, host, port);
}

void Http2SessionDriver::serve_static(int32_t stream_id, int status,
                                      const std::string& content_type,
                                      const std::string& body) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        streams_[stream_id] = StreamState{};
        it = streams_.find(stream_id);
    }
    it->second.response_started = true;
    it->second.static_body = body;
    it->second.static_body_offset = 0;

    // 使用静态字符串确保生命周期正确
    static const char* const_status = ":status";
    static const char* const_server = "server";
    static const char* const_nginx = "nginx";
    static const char* const_content_type = "content-type";

    const char* status_str = nullptr;
    switch (status) {
        case 200: status_str = "200"; break;
        case 204: status_str = "204"; break;
        case 206: status_str = "206"; break;
        case 304: status_str = "304"; break;
        case 400: status_str = "400"; break;
        case 403: status_str = "403"; break;
        case 404: status_str = "404"; break;
        case 500: status_str = "500"; break;
        default: status_str = "500"; break;
    }

    std::vector<nghttp2_nv> hdrs;

    nghttp2_nv nv_status{};
    nv_status.name = reinterpret_cast<uint8_t*>(const_cast<char*>(const_status));
    nv_status.namelen = 7;
    nv_status.value = reinterpret_cast<uint8_t*>(const_cast<char*>(status_str));
    nv_status.valuelen = 3;
    nv_status.flags = NGHTTP2_NV_FLAG_NONE;
    hdrs.push_back(nv_status);

    nghttp2_nv nv_server{};
    nv_server.name = reinterpret_cast<uint8_t*>(const_cast<char*>(const_server));
    nv_server.namelen = 6;
    nv_server.value = reinterpret_cast<uint8_t*>(const_cast<char*>(const_nginx));
    nv_server.valuelen = 5;
    nv_server.flags = NGHTTP2_NV_FLAG_NONE;
    hdrs.push_back(nv_server);

    if (!content_type.empty()) {
        nghttp2_nv nv_ct{};
        nv_ct.name = reinterpret_cast<uint8_t*>(const_cast<char*>(const_content_type));
        nv_ct.namelen = 12;
        nv_ct.value = reinterpret_cast<uint8_t*>(const_cast<char*>(content_type.data()));
        nv_ct.valuelen = content_type.size();
        nv_ct.flags = NGHTTP2_NV_FLAG_NONE;
        hdrs.push_back(nv_ct);
    }

    if (body.empty()) {
        nghttp2_submit_response2(session_, stream_id,
                                 hdrs.data(), hdrs.size(), nullptr);
        return;
    }

    nghttp2_data_provider2 provider{};
    provider.source.ptr    = nullptr;
    provider.read_callback = &Http2SessionDriver::static_body_read_callback;

    nghttp2_submit_response2(session_, stream_id,
                              hdrs.data(), hdrs.size(), &provider);
}

// static
bool Http2SessionDriver::parse_authority(const std::string& authority,
                                          std::string& host, uint16_t& port) {
    if (authority.empty()) return false;
    // IPv6: [::1]:port
    if (authority.front() == '[') {
        const auto end   = authority.find(']');
        const auto colon = authority.rfind(':');
        if (end == std::string::npos || colon == std::string::npos || colon <= end)
            return false;
        host = authority.substr(1, end - 1);
        try { port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1))); }
        catch (...) { return false; }
        return !host.empty() && port > 0;
    }
    const auto colon = authority.rfind(':');
    if (colon == std::string::npos) return false;
    host = authority.substr(0, colon);
    try { port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1))); }
    catch (...) { return false; }
    return !host.empty() && port > 0;
}
