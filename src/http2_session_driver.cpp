#include "http2_session_driver.h"

#include "homepage_html.h"

#include <cstring>
#include <sstream>
#include <utility>

#ifdef _WIN32
#else
#include <strings.h>
#endif

namespace {

constexpr std::int32_t kHttp2WindowSize = 16 * 1024 * 1024;
constexpr std::uint32_t kHttp2MaxFrameSize = 1024 * 1024;

using proxy::decode_open_request;
using proxy::encode_open_fail;
using proxy::FrameHeader;
using proxy::FrameType;
using proxy::select_http2_padded_length;
using proxy::to_bytes;

struct HeaderField {
    std::string name;
    std::string value;
};

nghttp2_nv make_nv(const std::string& name, const std::string& value) {
    nghttp2_nv nv{};
    nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data()));
    nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
    nv.namelen = name.size();
    nv.valuelen = value.size();
    return nv;
}

std::vector<HeaderField> make_response_header_fields(int status, const std::string& content_type) {
    std::vector<HeaderField> fields;
    fields.push_back({":status", std::to_string(status)});
    fields.push_back({"server", "nginx"});
    if (!content_type.empty()) fields.push_back({"content-type", content_type});
    return fields;
}

void append_cover_headers(std::vector<HeaderField>& fields, bool html_body) {
    fields.push_back({"cache-control", "public, max-age=300"});
    fields.push_back({"vary", "Accept-Encoding"});
    fields.push_back({"x-content-type-options", "nosniff"});
    fields.push_back({"x-frame-options", "SAMEORIGIN"});
    fields.push_back({"referrer-policy", "strict-origin-when-cross-origin"});
    if (html_body) fields.push_back({"content-language", "en"});
}

int ascii_casecmp(const char* lhs, const char* rhs) {
#ifdef _WIN32
    return _stricmp(lhs, rhs);
#else
    return strcasecmp(lhs, rhs);
#endif
}

std::string homepage_html() { return generated::kHomepageHtml; }

} // namespace

Http2SessionDriver::Http2SessionDriver(ServerConfig config, Callbacks callbacks)
    : config_(std::move(config)), callbacks_(std::move(callbacks)) {}

Http2SessionDriver::~Http2SessionDriver() {
    if (session_ != nullptr) nghttp2_session_del(session_);
}

bool Http2SessionDriver::initialize(std::vector<std::uint8_t>& tls_out) {
    nghttp2_session_callbacks* callbacks = nullptr;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &Http2SessionDriver::on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, &Http2SessionDriver::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &Http2SessionDriver::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &Http2SessionDriver::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &Http2SessionDriver::on_stream_close);
    nghttp2_session_callbacks_set_select_padding_callback2(callbacks, &Http2SessionDriver::select_padding);
    if (nghttp2_session_server_new(&session_, callbacks, this) != 0) {
        nghttp2_session_callbacks_del(callbacks);
        return false;
    }
    nghttp2_session_callbacks_del(callbacks);
    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, static_cast<uint32_t>(kHttp2WindowSize)},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, kHttp2MaxFrameSize},
    };
    if (nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, settings, 2) != 0 ||
        nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, 0, kHttp2WindowSize) != 0) {
        return false;
    }
    if (!queue_session_output()) return false;
    drain_tls_output(tls_out);
    return true;
}

bool Http2SessionDriver::receive(const std::uint8_t* data, std::size_t len, std::vector<std::uint8_t>& tls_out) {
    const auto consumed = nghttp2_session_mem_recv2(session_, data, len);
    if (consumed < 0) return false;
    if (!queue_session_output()) return false;
    drain_tls_output(tls_out);
    return true;
}

bool Http2SessionDriver::prepare_output(std::vector<std::uint8_t>& tls_out, std::size_t budget_bytes) {
    if (session_ == nullptr || event_stream_id_ < 0) return true;
    if (!downlink_control_.empty() || has_pending_downlink_data()) {
        nghttp2_session_resume_data(session_, event_stream_id_);
        if (!queue_session_output(budget_bytes)) return false;
        drain_tls_output(tls_out);
    }
    return true;
}

void Http2SessionDriver::enqueue_downlink(proxy::FrameType type, std::uint32_t stream_id,
                                          const std::vector<std::uint8_t>& payload,
                                          std::vector<std::uint8_t>& tls_out, std::size_t budget_bytes) {
    DownlinkFrame frame;
    frame.type = type;
    frame.stream_id = stream_id;
    proxy::append_frame(frame.encoded, type, stream_id, payload);
    if (type == FrameType::Data) {
        auto& stream_queue = downlink_data_by_stream_[stream_id];
        if (stream_queue.empty()) downlink_data_round_robin_.push_back(stream_id);
        stream_queue.push_back(std::move(frame));
    } else {
        downlink_control_.push_back(std::move(frame));
    }
    prepare_output(tls_out, budget_bytes);
    drain_tls_output(tls_out);
}

void Http2SessionDriver::purge_downlink_data_for_stream(std::uint32_t stream_id) {
    downlink_data_by_stream_.erase(stream_id);
    for (auto it = downlink_data_round_robin_.begin(); it != downlink_data_round_robin_.end();) {
        if (*it == stream_id) it = downlink_data_round_robin_.erase(it);
        else ++it;
    }
}

int32_t Http2SessionDriver::event_stream_id() const { return event_stream_id_; }
bool Http2SessionDriver::shutdown_requested() const { return shutdown_requested_; }

bool Http2SessionDriver::queue_session_output(std::size_t budget_bytes) {
    if (session_ == nullptr) return true;
    std::size_t sent = 0;
    while (sent < budget_bytes) {
        const uint8_t* data = nullptr;
        const auto len = nghttp2_session_mem_send2(session_, &data);
        if (len < 0) return false;
        if (len == 0) return true;
        pending_tls_out_.insert(pending_tls_out_.end(), data, data + len);
        sent += static_cast<std::size_t>(len);
    }
    return true;
}

void Http2SessionDriver::drain_tls_output(std::vector<std::uint8_t>& tls_out) {
    if (pending_tls_out_.empty()) return;
    if (&tls_out == &pending_tls_out_) return;
    tls_out.insert(tls_out.end(), pending_tls_out_.begin(), pending_tls_out_.end());
    pending_tls_out_.clear();
}

bool Http2SessionDriver::has_pending_downlink_data() const { return !downlink_data_round_robin_.empty(); }

Http2SessionDriver::DownlinkFrame* Http2SessionDriver::current_downlink_data_frame() {
    while (!downlink_data_round_robin_.empty()) {
        const std::uint32_t stream_id = downlink_data_round_robin_.front();
        const auto stream_it = downlink_data_by_stream_.find(stream_id);
        if (stream_it == downlink_data_by_stream_.end() || stream_it->second.empty()) {
            downlink_data_round_robin_.pop_front();
            if (stream_it != downlink_data_by_stream_.end() && stream_it->second.empty()) {
                downlink_data_by_stream_.erase(stream_it);
            }
            continue;
        }
        return &stream_it->second.front();
    }
    return nullptr;
}

std::string Http2SessionDriver::get_header_value_ci(const RequestState& request, const std::string& name) const {
    for (const auto& kv : request.headers) {
        if (ascii_casecmp(kv.first.c_str(), name.c_str()) == 0) return kv.second;
    }
    return {};
}

bool Http2SessionDriver::is_authorized(const RequestState& request) const {
    if (config_.auth_password.empty()) return true;
    if (request.path.rfind("/api/tunnel/", 0) != 0) return true;
    return get_header_value_ci(request, "x-tunnel-auth") == config_.auth_password;
}

void Http2SessionDriver::submit_static_response(int32_t stream_id, int status, const std::string& content_type,
                                                const std::vector<std::uint8_t>& body,
                                                std::vector<std::uint8_t>& tls_out) {
    auto& request = requests_[stream_id];
    request.response_mode = RequestState::ResponseMode::StaticBody;
    request.response_body = body;
    request.response_offset = 0;
    request.response_started = true;
    auto header_fields = make_response_header_fields(status, content_type);
    if (status == 200 && content_type.find("text/html") != std::string::npos) append_cover_headers(header_fields, true);
    std::vector<nghttp2_nv> headers;
    headers.reserve(header_fields.size());
    for (const auto& field : header_fields) headers.push_back(make_nv(field.name, field.value));
    nghttp2_data_provider2 provider{};
    nghttp2_data_provider2* provider_ptr = nullptr;
    if (!body.empty()) {
        provider.source.ptr = &request;
        provider.read_callback = &Http2SessionDriver::read_response_body;
        provider_ptr = &provider;
    }
    nghttp2_submit_response2(session_, stream_id, headers.data(), headers.size(), provider_ptr);
    queue_session_output();
    drain_tls_output(tls_out);
}

void Http2SessionDriver::handle_request(int32_t stream_id, std::vector<std::uint8_t>& tls_out) {
    auto it = requests_.find(stream_id);
    if (it == requests_.end()) return;
    auto& request = it->second;
    if (!is_authorized(request)) {
        submit_static_response(stream_id, 403, "text/plain", to_bytes("forbidden"), tls_out);
        return;
    }
    if (request.method == "GET" && request.path == "/") {
        submit_static_response(stream_id, 200, "text/html; charset=utf-8", to_bytes(homepage_html()), tls_out);
        return;
    }
    if (request.method == "POST" && request.path == "/api/tunnel/open") {
        if (tunnel_opened_) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("tunnel already opened"), tls_out);
            return;
        }
        tunnel_opened_ = true;
        submit_static_response(stream_id, 200, "text/plain", to_bytes("ok"), tls_out);
        return;
    }
    if (request.method == "GET" && request.path == "/api/tunnel/events") {
        if (!tunnel_opened_) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("open stream required first"), tls_out);
            return;
        }
        if (event_stream_id_ >= 0) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("event stream already exists"), tls_out);
            return;
        }
        request.response_mode = RequestState::ResponseMode::EventStream;
        request.response_offset = 0;
        event_stream_id_ = stream_id;
        if (nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, stream_id, kHttp2WindowSize) != 0) {
            submit_static_response(stream_id, 500, "text/plain", to_bytes("failed to set event stream window"),
                                   tls_out);
            return;
        }
        const auto header_fields = make_response_header_fields(200, "application/octet-stream");
        std::vector<nghttp2_nv> headers;
        headers.reserve(header_fields.size());
        for (const auto& field : header_fields) headers.push_back(make_nv(field.name, field.value));
        nghttp2_data_provider2 provider{};
        provider.source.ptr = &request;
        provider.read_callback = &Http2SessionDriver::read_response_body;
        nghttp2_submit_response2(session_, stream_id, headers.data(), headers.size(), &provider);
        prepare_output(tls_out, static_cast<std::size_t>(-1));
        return;
    }
    if (request.method == "POST" && request.path == "/api/tunnel/upload") {
        if (request.response_started) return;
        if (!tunnel_opened_) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("open stream required first"), tls_out);
            return;
        }
        submit_static_response(stream_id, 200, "text/plain", to_bytes("ok"), tls_out);
        nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, stream_id, kHttp2WindowSize);
        handle_upload_frames(request, tls_out);
        return;
    }
    if (request.method == "POST" && request.path == "/api/tunnel/close") {
        submit_static_response(stream_id, 200, "text/plain", to_bytes("closed"), tls_out);
        shutdown_requested_ = true;
        if (event_stream_id_ >= 0) nghttp2_session_resume_data(session_, event_stream_id_);
        if (callbacks_.on_close_all_upstreams) callbacks_.on_close_all_upstreams();
        queue_session_output();
        drain_tls_output(tls_out);
        return;
    }
    submit_static_response(stream_id, 404, "text/plain", to_bytes("not found"), tls_out);
}

void Http2SessionDriver::handle_upload_frames(RequestState& request, std::vector<std::uint8_t>& tls_out) {
    std::vector<std::pair<FrameHeader, std::vector<std::uint8_t>>> frames;
    if (!proxy::consume_frames(request.body, frames)) {
        request.body.clear();
        return;
    }
    for (const auto& item : frames) {
        const FrameType type = static_cast<FrameType>(item.first.type);
        const std::uint32_t tunnel_stream_id = proxy::to_be32(item.first.stream_id);
        if (type == FrameType::Open) {
            std::uint8_t atyp = 0;
            std::string requested_host;
            std::uint16_t requested_port = 0;
            if (!decode_open_request(item.second, atyp, requested_host, requested_port)) {
                enqueue_downlink(FrameType::OpenFail, tunnel_stream_id, encode_open_fail("bad open request"), tls_out,
                                 static_cast<std::size_t>(-1));
                continue;
            }
            if (callbacks_.on_open_stream) {
                callbacks_.on_open_stream(tunnel_stream_id, atyp, requested_host, requested_port);
            }
        } else if (type == FrameType::Data) {
            if (callbacks_.on_stream_data) callbacks_.on_stream_data(tunnel_stream_id, item.second);
        } else if (type == FrameType::Close) {
            if (callbacks_.on_stream_close) callbacks_.on_stream_close(tunnel_stream_id);
        } else if (type == FrameType::Ping) {
            enqueue_downlink(FrameType::Pong, 0, item.second, tls_out, static_cast<std::size_t>(-1));
        }
    }
}

nghttp2_ssize Http2SessionDriver::read_response_body(nghttp2_session*, int32_t, uint8_t* buf, size_t length,
                                                     uint32_t* data_flags, nghttp2_data_source* source,
                                                     void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    auto* request = static_cast<RequestState*>(source->ptr);
    if (request->response_mode == RequestState::ResponseMode::EventStream) {
        DownlinkFrame* active_frame = nullptr;
        if (!self->downlink_control_.empty()) active_frame = &self->downlink_control_.front();
        else active_frame = self->current_downlink_data_frame();
        if (active_frame == nullptr) {
            if (self->shutdown_requested_) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                return 0;
            }
            return NGHTTP2_ERR_DEFERRED;
        }
        const std::size_t available = active_frame->encoded.size() - active_frame->offset;
        const std::size_t copy_len = available < length ? available : length;
        std::memcpy(buf, active_frame->encoded.data() + active_frame->offset, copy_len);
        active_frame->offset += copy_len;
        if (active_frame->offset >= active_frame->encoded.size()) {
            if (!self->downlink_control_.empty()) {
                self->downlink_control_.pop_front();
            } else if (!self->downlink_data_round_robin_.empty()) {
                const std::uint32_t logical_stream_id = self->downlink_data_round_robin_.front();
                auto stream_it = self->downlink_data_by_stream_.find(logical_stream_id);
                if (stream_it != self->downlink_data_by_stream_.end() && !stream_it->second.empty()) {
                    stream_it->second.pop_front();
                    self->downlink_data_round_robin_.pop_front();
                    if (!stream_it->second.empty()) self->downlink_data_round_robin_.push_back(logical_stream_id);
                    else self->downlink_data_by_stream_.erase(stream_it);
                } else {
                    self->downlink_data_round_robin_.pop_front();
                    if (stream_it != self->downlink_data_by_stream_.end()) self->downlink_data_by_stream_.erase(stream_it);
                }
            }
            if (self->shutdown_requested_ && self->downlink_control_.empty() && !self->has_pending_downlink_data()) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            } else if (!self->downlink_control_.empty() || self->has_pending_downlink_data()) {
                nghttp2_session_resume_data(self->session_, self->event_stream_id_);
            }
        }
        return static_cast<nghttp2_ssize>(copy_len);
    }
    const std::size_t remaining = request->response_body.size() - request->response_offset;
    const std::size_t copy_len = remaining < length ? remaining : length;
    if (copy_len > 0) {
        std::memcpy(buf, request->response_body.data() + request->response_offset, copy_len);
        request->response_offset += copy_len;
    }
    if (request->response_offset >= request->response_body.size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(copy_len);
}

int Http2SessionDriver::on_begin_headers(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        self->requests_[frame->hd.stream_id] = RequestState{};
    }
    return 0;
}

int Http2SessionDriver::on_header(nghttp2_session*, const nghttp2_frame* frame, const uint8_t* name, size_t namelen,
                                  const uint8_t* value, size_t valuelen, uint8_t, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    auto it = self->requests_.find(frame->hd.stream_id);
    if (it == self->requests_.end()) return 0;
    const std::string header_name(reinterpret_cast<const char*>(name), namelen);
    const std::string header_value(reinterpret_cast<const char*>(value), valuelen);
    if (header_name == ":method") it->second.method = header_value;
    else if (header_name == ":path") it->second.path = header_value;
    else it->second.headers[header_name] = header_value;
    return 0;
}

int Http2SessionDriver::on_data_chunk_recv(nghttp2_session*, uint8_t, int32_t stream_id, const uint8_t* data,
                                           size_t len, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    auto it = self->requests_.find(stream_id);
    if (it == self->requests_.end()) return 0;
    it->second.body.insert(it->second.body.end(), data, data + len);
    if (it->second.method == "POST" && it->second.path == "/api/tunnel/upload") {
        self->handle_upload_frames(it->second, self->pending_tls_out_);
    }
    return 0;
}

int Http2SessionDriver::on_frame_recv(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        const auto it = self->requests_.find(frame->hd.stream_id);
        if (it != self->requests_.end() && it->second.method == "POST" && it->second.path == "/api/tunnel/upload" &&
            !it->second.response_started) {
            self->handle_request(frame->hd.stream_id, self->pending_tls_out_);
        }
    }
    if (((frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) ||
         frame->hd.type == NGHTTP2_DATA) &&
        ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0)) {
        self->handle_request(frame->hd.stream_id, self->pending_tls_out_);
    }
    return 0;
}

int Http2SessionDriver::on_stream_close(nghttp2_session*, int32_t stream_id, uint32_t, void* user_data) {
    auto* self = static_cast<Http2SessionDriver*>(user_data);
    self->requests_.erase(stream_id);
    if (stream_id == self->event_stream_id_) self->event_stream_id_ = -1;
    return 0;
}

nghttp2_ssize Http2SessionDriver::select_padding(nghttp2_session*, const nghttp2_frame* frame, size_t max_payloadlen,
                                                 void*) {
    return static_cast<nghttp2_ssize>(
        select_http2_padded_length(frame->hd.type, frame->hd.length, max_payloadlen));
}
