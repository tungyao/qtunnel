#include "common/logging.h"
#include "common/socks5.h"
#include "common/tls_wrapper.h"
#include "common/tunnel_protocol.h"

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <cstdint>
#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace {

using proxy::close_socket;
using proxy::consume_frames;
using proxy::decode_open_fail;
using proxy::encode_open_request;
using proxy::FrameHeader;
using proxy::FrameType;
using proxy::kInvalidSocket;
using proxy::parse_frames;
using proxy::parse_log_level;
using proxy::perform_socks5_handshake;
using proxy::send_socks5_reply;
using proxy::set_log_level;
using proxy::select_http2_padded_length;
using proxy::socket_t;
using proxy::LogLevel;
using proxy::Socks5HandshakeStatus;
using proxy::Socks5Request;
using proxy::TlsSocket;

struct ClientConfig {
    std::string server_host;
    std::uint16_t server_port = 8443;
    std::uint16_t listen_port = 1080;
    std::string auth_password;
    std::string ech_config;
    bool enable_ech_grease = true;
    LogLevel log_level = LogLevel::Info;
};

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
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

std::vector<HeaderField> make_request_header_fields(const ClientConfig& cfg, const std::string& method,
                                                    const std::string& path, const std::string& content_type,
                                                    bool has_body) {
    std::vector<HeaderField> fields;
    fields.push_back({":method", method});
    fields.push_back({":scheme", "https"});
    fields.push_back({":authority", cfg.server_host + ":" + std::to_string(cfg.server_port)});
    fields.push_back({":path", path});
    fields.push_back({"user-agent", "qtunnel-h2-client/1.0"});
    fields.push_back({"accept", "*/*"});
    if (!cfg.auth_password.empty()) {
        fields.push_back({"x-tunnel-auth", cfg.auth_password});
    }
    if (has_body) {
        fields.push_back({"content-type", content_type});
    }

    return fields;
}

bool parse_host_port(const std::string& text, std::string& host, std::uint16_t& port) {
    if (text.empty()) {
        return false;
    }
    if (text.front() == '[') {
        const auto end = text.find(']');
        const auto colon = text.rfind(':');
        if (end == std::string::npos || colon == std::string::npos || colon <= end) {
            return false;
        }
        host = text.substr(1, end - 1);
        port = static_cast<std::uint16_t>(std::stoi(text.substr(colon + 1)));
        return true;
    }
    const auto colon = text.rfind(':');
    if (colon == std::string::npos) {
        return false;
    }
    host = text.substr(0, colon);
    port = static_cast<std::uint16_t>(std::stoi(text.substr(colon + 1)));
    return !host.empty();
}

class ClientRuntime {
public:
    explicit ClientRuntime(ClientConfig cfg) : cfg_(std::move(cfg)) {}
    ~ClientRuntime();

    bool start();

private:
    struct LocalStream {
        std::uint32_t id = 0;
        socket_t sock = kInvalidSocket;
        enum class State { Pending, Open, Failed, Closed } state = State::Pending;
        std::string error;
        std::mutex mutex;
        std::condition_variable cv;
    };

    struct RequestState {
        enum class WaitMode {
            UntilHeaders,
            UntilStreamClose
        };

        std::string method;
        std::string path;
        std::string content_type;
        std::vector<std::uint8_t> body;
        std::size_t body_offset = 0;
        int status = 0;
        bool success = false;
        bool done = false;
        bool long_lived = false;
        WaitMode wait_mode = WaitMode::UntilStreamClose;
        int32_t stream_id = -1;
        std::string error;
        std::mutex mutex;
        std::condition_variable cv;
    };

    bool wait_for_io_ready();
    bool submit_request_sync(const std::string& method, const std::string& path,
                             const std::vector<std::uint8_t>& body, const std::string& content_type,
                             RequestState::WaitMode wait_mode, bool long_lived, int* status_out = nullptr);
    bool start_event_stream();
    void io_loop();
    void upload_loop();
    void accept_and_pump_loop();
    void accept_one();
    void pump_local_socket(const std::shared_ptr<LocalStream>& stream);
    void queue_frame(FrameType type, std::uint32_t stream_id, const std::vector<std::uint8_t>& payload);
    void dispatch_downlink(const std::vector<std::uint8_t>& body);
    void close_stream(std::uint32_t id, bool notify_remote);
    void close_all_streams();
    void process_request_queue();
    bool flush_session();

    static socket_t make_listener(std::uint16_t port);
    static nghttp2_ssize read_request_body(nghttp2_session* session, int32_t stream_id, uint8_t* buf,
                                           size_t length, uint32_t* data_flags, nghttp2_data_source* source,
                                           void* user_data);
    static int on_begin_headers(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
    static int on_header(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name,
                         size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags,
                         void* user_data);
    static int on_data_chunk_recv(nghttp2_session* session, uint8_t flags, int32_t stream_id,
                                  const uint8_t* data, size_t len, void* user_data);
    static int on_frame_recv(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
    static int on_stream_close(nghttp2_session* session, int32_t stream_id, uint32_t error_code,
                               void* user_data);
    static nghttp2_ssize select_padding(nghttp2_session* session, const nghttp2_frame* frame,
                                        size_t max_payloadlen, void* user_data);

    ClientConfig cfg_;
    socket_t listener_ = kInvalidSocket;
    TlsSocket tls_;
    nghttp2_session* h2_ = nullptr;
    std::thread io_thread_;
    std::thread upload_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> io_ready_{false};
    std::atomic<bool> io_ok_{false};
    std::string io_error_;
    std::string peer_fingerprint_;

    std::mutex requests_mutex_;
    std::deque<std::shared_ptr<RequestState>> pending_requests_;
    std::map<int32_t, std::shared_ptr<RequestState>> active_requests_;

    std::mutex upload_mutex_;
    std::condition_variable upload_cv_;
    std::vector<std::uint8_t> upload_buffer_;

    std::mutex streams_mutex_;
    std::map<std::uint32_t, std::shared_ptr<LocalStream>> streams_;
    std::uint32_t next_stream_id_ = 1;
    std::vector<std::uint8_t> downlink_buffer_;

    int32_t event_stream_id_ = -1;
};

ClientRuntime::~ClientRuntime() {
    const bool was_running = running_.exchange(false);
    upload_cv_.notify_all();
    if (was_running) {
        int ignored_status = 0;
        submit_request_sync("POST", "/api/tunnel/close", {}, "text/plain",
                            RequestState::WaitMode::UntilStreamClose, false, &ignored_status);
    }
    if (listener_ != kInvalidSocket) {
        close_socket(listener_);
    }
    tls_.shutdown();
    if (upload_thread_.joinable()) {
        upload_thread_.join();
    }
    if (io_thread_.joinable()) {
        io_thread_.join();
    }
    if (h2_ != nullptr) {
        nghttp2_session_del(h2_);
        h2_ = nullptr;
    }
    close_all_streams();
}

bool ClientRuntime::wait_for_io_ready() {
    for (int i = 0; i < 200; ++i) {
        if (io_ready_) {
            return io_ok_;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    io_error_ = "等待 HTTP/2 连接初始化超时";
    return false;
}

bool ClientRuntime::submit_request_sync(const std::string& method, const std::string& path,
                                        const std::vector<std::uint8_t>& body, const std::string& content_type,
                                        RequestState::WaitMode wait_mode, bool long_lived, int* status_out) {
    if (!running_) {
        io_error_ = "客户端未运行";
        return false;
    }

    auto request = std::make_shared<RequestState>();
    request->method = method;
    request->path = path;
    request->body = body;
    request->content_type = content_type;
    request->wait_mode = wait_mode;
    request->long_lived = long_lived;

    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        pending_requests_.push_back(request);
    }

    std::unique_lock<std::mutex> lock(request->mutex);
    const bool completed = request->cv.wait_for(lock, std::chrono::seconds(15), [&] {
        return request->done || !running_;
    });

    if (!completed) {
        request->done = true;
        request->success = false;
        request->error = "等待服务端响应超时: " + method + " " + path;
    }

    if (status_out != nullptr) {
        *status_out = request->status;
    }
    if (!request->success && !request->error.empty()) {
        io_error_ = request->error;
    }
    return request->success;
}

bool ClientRuntime::start_event_stream() {
    int status = 0;
    if (!submit_request_sync("GET", "/api/tunnel/events", {}, "application/octet-stream",
                             RequestState::WaitMode::UntilHeaders, true, &status)) {
        return false;
    }
    if (status != 200) {
        io_error_ = "建立事件流失败, HTTP " + std::to_string(status);
        return false;
    }
    return true;
}

bool ClientRuntime::start() {
    running_ = true;
    PROXY_LOG(Info, "[client] 正在连接 " << cfg_.server_host << ":" << cfg_.server_port << " ...");
    io_thread_ = std::thread(&ClientRuntime::io_loop, this);
    if (!wait_for_io_ready()) {
        PROXY_LOG(Error, "[client] HTTP/2 初始化失败: " << io_error_);
        running_ = false;
        tls_.shutdown();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
        return false;
    }

    int open_status = 0;
    PROXY_LOG(Info, "[client] 正在打开隧道 stream ...");
    if (!submit_request_sync("POST", "/api/tunnel/open", {}, "text/plain",
                             RequestState::WaitMode::UntilStreamClose, false, &open_status) ||
        open_status != 200) {
        PROXY_LOG(Error, "[client] 打开隧道失败: "
                            << (io_error_.empty() ? ("HTTP " + std::to_string(open_status)) : io_error_));
        running_ = false;
        tls_.shutdown();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
        return false;
    }

    PROXY_LOG(Info, "[client] 正在建立下行事件 stream ...");
    if (!start_event_stream()) {
        PROXY_LOG(Error, "[client] 启动事件流失败: " << io_error_);
        running_ = false;
        tls_.shutdown();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
        return false;
    }

    listener_ = make_listener(cfg_.listen_port);
    if (listener_ == kInvalidSocket) {
        PROXY_LOG(Error, "[client] 本地监听失败");
        running_ = false;
        return false;
    }

    upload_thread_ = std::thread(&ClientRuntime::upload_loop, this);
    PROXY_LOG(Info, "[client] HTTP/2 TLS 连接已建立到 " << cfg_.server_host << ":" << cfg_.server_port);
    if (!peer_fingerprint_.empty()) {
        PROXY_LOG(Debug, "[client] 服务器证书 SHA-256 指纹: " << peer_fingerprint_);
    }
    PROXY_LOG(Info, "[client] SOCKS5 监听 127.0.0.1:" << cfg_.listen_port);
    accept_and_pump_loop();
    return true;
}

void ClientRuntime::io_loop() {
    nghttp2_session_callbacks* callbacks = nullptr;
    const auto finish_with_error = [&](const std::string& error) {
        io_error_ = error;
        io_ok_ = false;
        io_ready_ = true;
        running_ = false;
    };

    tls_.set_enable_ech_grease(cfg_.enable_ech_grease);
    tls_.set_ech_config_base64(cfg_.ech_config);
    if (!tls_.connect_client(cfg_.server_host, cfg_.server_port, cfg_.server_host)) {
        finish_with_error(tls_.last_error());
        return;
    }
    peer_fingerprint_ = tls_.peer_fingerprint();
    PROXY_LOG(Debug, "[client] TLS version: " << tls_.negotiated_tls_version());
    PROXY_LOG(Debug, "[client] TLS cipher: " << tls_.negotiated_cipher());
    PROXY_LOG(Debug, "[client] TLS ALPN: " << (tls_.negotiated_alpn().empty() ? "<none>" : tls_.negotiated_alpn()));
    PROXY_LOG(Debug, "[client] TLS ECH accepted: " << (tls_.ech_accepted() ? "yes" : "no"));
    if (!tls_.ech_name_override().empty()) {
        PROXY_LOG(Debug, "[client] TLS ECH name override: " << tls_.ech_name_override());
    }

    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &ClientRuntime::on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, &ClientRuntime::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &ClientRuntime::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &ClientRuntime::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &ClientRuntime::on_stream_close);
    nghttp2_session_callbacks_set_select_padding_callback2(callbacks, &ClientRuntime::select_padding);

    if (nghttp2_session_client_new(&h2_, callbacks, this) != 0) {
        nghttp2_session_callbacks_del(callbacks);
        finish_with_error("nghttp2_session_client_new 失败");
        return;
    }
    nghttp2_session_callbacks_del(callbacks);

    if (nghttp2_submit_settings(h2_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0 || !flush_session()) {
        finish_with_error("发送 HTTP/2 SETTINGS 失败");
        return;
    }

    io_ok_ = true;
    io_ready_ = true;

    while (running_) {
        process_request_queue();

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tls_.raw_socket(), &readfds);
        timeval tv{};
        tv.tv_usec = 100000;
        const int ready = ::select(static_cast<int>(tls_.raw_socket() + 1), &readfds, nullptr, nullptr, &tv);
        if (ready > 0 && FD_ISSET(tls_.raw_socket(), &readfds)) {
            std::array<std::uint8_t, 16384> buf{};
            const int ret = tls_.read(buf.data(), buf.size());
            if (ret <= 0) {
                io_error_ = tls_.last_error().empty() ? "HTTP/2 连接已断开" : tls_.last_error();
                running_ = false;
                break;
            }
            const auto consumed = nghttp2_session_mem_recv2(h2_, buf.data(), static_cast<size_t>(ret));
            if (consumed < 0) {
                io_error_ = std::string("nghttp2_session_mem_recv2 失败: ") + nghttp2_strerror(static_cast<int>(consumed));
                running_ = false;
                break;
            }
            if (!flush_session()) {
                io_error_ = "发送 HTTP/2 帧失败";
                running_ = false;
                break;
            }
        }
    }

    std::lock_guard<std::mutex> lock(requests_mutex_);
    for (auto& item : active_requests_) {
        std::lock_guard<std::mutex> req_lock(item.second->mutex);
        item.second->done = true;
        item.second->success = false;
        if (item.second->error.empty()) {
            item.second->error = io_error_.empty() ? "HTTP/2 会话已结束" : io_error_;
        }
        item.second->cv.notify_all();
    }
    while (!pending_requests_.empty()) {
        auto req = pending_requests_.front();
        pending_requests_.pop_front();
        std::lock_guard<std::mutex> req_lock(req->mutex);
        req->done = true;
        req->success = false;
        req->error = io_error_.empty() ? "HTTP/2 会话已结束" : io_error_;
        req->cv.notify_all();
    }
}

void ClientRuntime::process_request_queue() {
    std::deque<std::shared_ptr<RequestState>> queue;
    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        queue.swap(pending_requests_);
    }

    for (auto& request : queue) {
        const auto header_fields = make_request_header_fields(cfg_, request->method, request->path,
                                                              request->content_type, !request->body.empty());
        std::vector<nghttp2_nv> headers;
        headers.reserve(header_fields.size());
        for (const auto& field : header_fields) {
            headers.push_back(make_nv(field.name, field.value));
        }
        nghttp2_data_provider2 provider{};
        nghttp2_data_provider2* provider_ptr = nullptr;
        if (!request->body.empty()) {
            provider.source.ptr = request.get();
            provider.read_callback = &ClientRuntime::read_request_body;
            provider_ptr = &provider;
        }

        const int32_t stream_id = nghttp2_submit_request2(h2_, nullptr, headers.data(), headers.size(),
                                                          provider_ptr, request.get());
        if (stream_id < 0) {
            std::lock_guard<std::mutex> lock(request->mutex);
            request->done = true;
            request->success = false;
            request->error = std::string("nghttp2_submit_request2 失败: ") + nghttp2_strerror(stream_id);
            request->cv.notify_all();
            continue;
        }

        request->stream_id = stream_id;
        {
            std::lock_guard<std::mutex> lock(requests_mutex_);
            active_requests_[stream_id] = request;
        }
        if (!flush_session()) {
            std::lock_guard<std::mutex> lock(request->mutex);
            request->done = true;
            request->success = false;
            request->error = "发送 HTTP/2 请求失败";
            request->cv.notify_all();
        }
    }
}

bool ClientRuntime::flush_session() {
    while (true) {
        const uint8_t* data = nullptr;
        const auto len = nghttp2_session_mem_send2(h2_, &data);
        if (len < 0) {
            return false;
        }
        if (len == 0) {
            return true;
        }
        if (!tls_.write_all(data, static_cast<std::size_t>(len))) {
            return false;
        }
    }
}

nghttp2_ssize ClientRuntime::read_request_body(nghttp2_session* /*session*/, int32_t /*stream_id*/, uint8_t* buf,
                                               size_t length, uint32_t* data_flags, nghttp2_data_source* source,
                                               void* /*user_data*/) {
    auto* request = static_cast<RequestState*>(source->ptr);
    const std::size_t remaining = request->body.size() - request->body_offset;
    const std::size_t copy_len = remaining < length ? remaining : length;
    if (copy_len > 0) {
        std::memcpy(buf, request->body.data() + request->body_offset, copy_len);
        request->body_offset += copy_len;
    }
    if (request->body_offset >= request->body.size()) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return static_cast<nghttp2_ssize>(copy_len);
}

int ClientRuntime::on_begin_headers(nghttp2_session* /*session*/, const nghttp2_frame* /*frame*/, void* /*user_data*/) {
    return 0;
}

int ClientRuntime::on_header(nghttp2_session* /*session*/, const nghttp2_frame* frame, const uint8_t* name,
                             size_t namelen, const uint8_t* value, size_t valuelen, uint8_t /*flags*/,
                             void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
        return 0;
    }

    auto* self = static_cast<ClientRuntime*>(user_data);
    std::shared_ptr<RequestState> request;
    {
        std::lock_guard<std::mutex> lock(self->requests_mutex_);
        const auto it = self->active_requests_.find(frame->hd.stream_id);
        if (it == self->active_requests_.end()) {
            return 0;
        }
        request = it->second;
    }

    const std::string header_name(reinterpret_cast<const char*>(name), namelen);
    if (header_name == ":status") {
        request->status = std::stoi(std::string(reinterpret_cast<const char*>(value), valuelen));
        PROXY_LOG(Debug, "[client] stream " << frame->hd.stream_id << " HTTP status " << request->status);
    }
    return 0;
}

int ClientRuntime::on_data_chunk_recv(nghttp2_session* /*session*/, uint8_t /*flags*/, int32_t stream_id,
                                      const uint8_t* data, size_t len, void* user_data) {
    auto* self = static_cast<ClientRuntime*>(user_data);
    if (stream_id == self->event_stream_id_) {
        self->dispatch_downlink(std::vector<std::uint8_t>(data, data + len));
    }
    return 0;
}

int ClientRuntime::on_frame_recv(nghttp2_session* /*session*/, const nghttp2_frame* frame, void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) {
        return 0;
    }

    auto* self = static_cast<ClientRuntime*>(user_data);
    std::shared_ptr<RequestState> request;
    {
        std::lock_guard<std::mutex> lock(self->requests_mutex_);
        const auto it = self->active_requests_.find(frame->hd.stream_id);
        if (it == self->active_requests_.end()) {
            return 0;
        }
        request = it->second;
    }

    if (frame->hd.type == NGHTTP2_HEADERS && request->wait_mode == RequestState::WaitMode::UntilHeaders &&
        frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
        {
            std::lock_guard<std::mutex> lock(request->mutex);
            request->done = true;
            request->success = request->status == 200;
            if (!request->success) {
                request->error = "HTTP " + std::to_string(request->status);
            }
        }
        request->cv.notify_all();
        if (request->long_lived) {
            self->event_stream_id_ = frame->hd.stream_id;
        }
        return 0;
    }

    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
        {
            std::lock_guard<std::mutex> lock(request->mutex);
            request->done = true;
            request->success = request->status == 200;
            if (!request->success) {
                request->error = "HTTP " + std::to_string(request->status);
            }
        }
        request->cv.notify_all();
    }
    return 0;
}

int ClientRuntime::on_stream_close(nghttp2_session* /*session*/, int32_t stream_id, uint32_t /*error_code*/,
                                   void* user_data) {
    auto* self = static_cast<ClientRuntime*>(user_data);
    std::shared_ptr<RequestState> request;
    {
        std::lock_guard<std::mutex> lock(self->requests_mutex_);
        const auto it = self->active_requests_.find(stream_id);
        if (it != self->active_requests_.end()) {
            request = it->second;
            if (!request->long_lived || stream_id != self->event_stream_id_) {
                self->active_requests_.erase(it);
            }
        }
    }

    if (request) {
        std::lock_guard<std::mutex> lock(request->mutex);
        if (!request->done) {
            request->done = true;
            request->success = request->status == 200;
            if (!request->success && request->error.empty()) {
                request->error = "HTTP " + std::to_string(request->status);
            }
            request->cv.notify_all();
        }
    }

    if (stream_id == self->event_stream_id_ && self->running_) {
        self->io_error_ = "下行事件流已关闭";
        self->running_ = false;
    }
    return 0;
}

nghttp2_ssize ClientRuntime::select_padding(nghttp2_session* /*session*/, const nghttp2_frame* frame,
                                            size_t max_payloadlen, void* /*user_data*/) {
    return static_cast<nghttp2_ssize>(
        select_http2_padded_length(frame->hd.type, frame->hd.length, max_payloadlen));
}

void ClientRuntime::queue_frame(FrameType type, std::uint32_t stream_id, const std::vector<std::uint8_t>& payload) {
    {
        std::lock_guard<std::mutex> lock(upload_mutex_);
        proxy::append_frame(upload_buffer_, type, stream_id, payload);
    }
    upload_cv_.notify_one();
}

void ClientRuntime::upload_loop() {
    while (running_) {
        std::vector<std::uint8_t> batch;
        {
            std::unique_lock<std::mutex> lock(upload_mutex_);
            upload_cv_.wait_for(lock, std::chrono::milliseconds(50), [&] {
                return !upload_buffer_.empty() || !running_;
            });
            batch.swap(upload_buffer_);
        }

        if (!running_) {
            break;
        }
        if (batch.empty()) {
            continue;
        }

        int status = 0;
        if (!submit_request_sync("POST", "/api/tunnel/upload", batch, "application/octet-stream",
                                 RequestState::WaitMode::UntilStreamClose, false, &status) ||
            status != 200) {
            PROXY_LOG(Error, "[client] upload 失败: "
                                << (io_error_.empty() ? ("HTTP " + std::to_string(status)) : io_error_));
            running_ = false;
            break;
        }
    }
}

void ClientRuntime::dispatch_downlink(const std::vector<std::uint8_t>& body) {
    downlink_buffer_.insert(downlink_buffer_.end(), body.begin(), body.end());
    std::vector<std::pair<FrameHeader, std::vector<std::uint8_t>>> frames;
    if (!consume_frames(downlink_buffer_, frames)) {
        PROXY_LOG(Error, "[client] 事件流负载损坏");
        running_ = false;
        return;
    }

    for (const auto& item : frames) {
        const FrameType type = static_cast<FrameType>(item.first.type);
        const std::uint32_t stream_id = proxy::to_be32(item.first.stream_id);
        if (type == FrameType::Pong) {
            continue;
        }

        std::shared_ptr<LocalStream> stream;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            const auto it = streams_.find(stream_id);
            if (it != streams_.end()) {
                stream = it->second;
            }
        }

        if (type == FrameType::OpenOk) {
            if (!stream) {
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(stream->mutex);
                stream->state = LocalStream::State::Open;
            }
            stream->cv.notify_all();
        } else if (type == FrameType::OpenFail) {
            if (!stream) {
                continue;
            }
            std::string reason;
            decode_open_fail(item.second, reason);
            {
                std::lock_guard<std::mutex> lock(stream->mutex);
                stream->state = LocalStream::State::Failed;
                stream->error = reason;
            }
            stream->cv.notify_all();
        } else if (type == FrameType::Data) {
            if (!stream) {
                continue;
            }
#ifdef _WIN32
            const int ret = ::send(stream->sock, reinterpret_cast<const char*>(item.second.data()),
                                   static_cast<int>(item.second.size()), 0);
#else
            const int ret = static_cast<int>(::send(stream->sock, item.second.data(), item.second.size(), 0));
#endif
            if (ret <= 0) {
                close_stream(stream_id, true);
            }
        } else if (type == FrameType::Close) {
            close_stream(stream_id, false);
        }
    }
}

void ClientRuntime::accept_and_pump_loop() {
    while (running_) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener_, &readfds);
        socket_t maxfd = listener_;

        std::vector<std::shared_ptr<LocalStream>> snapshot;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            for (const auto& kv : streams_) {
                snapshot.push_back(kv.second);
            }
        }
        for (const auto& stream : snapshot) {
            FD_SET(stream->sock, &readfds);
            if (stream->sock > maxfd) {
                maxfd = stream->sock;
            }
        }

        timeval tv{};
        tv.tv_sec = 1;
        const int ready = ::select(static_cast<int>(maxfd + 1), &readfds, nullptr, nullptr, &tv);
        if (ready < 0) {
            continue;
        }
        if (FD_ISSET(listener_, &readfds)) {
            accept_one();
        }
        for (const auto& stream : snapshot) {
            if (FD_ISSET(stream->sock, &readfds)) {
                pump_local_socket(stream);
            }
        }
    }
}

void ClientRuntime::accept_one() {
    sockaddr_storage ss{};
    socklen_t slen = sizeof(ss);
    socket_t sock = ::accept(listener_, reinterpret_cast<sockaddr*>(&ss), &slen);
    if (sock == kInvalidSocket) {
        return;
    }

    Socks5Request req;
    std::string error;
    const Socks5HandshakeStatus handshake_status = perform_socks5_handshake(sock, req, error);
    if (handshake_status != Socks5HandshakeStatus::Ok) {
        if (handshake_status == Socks5HandshakeStatus::Error) {
            PROXY_LOG(Warn, "[client] SOCKS5 握手失败: " << error);
        }
        close_socket(sock);
        return;
    }

    auto stream = std::make_shared<LocalStream>();
    stream->id = next_stream_id_++;
    stream->sock = sock;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_[stream->id] = stream;
    }

    queue_frame(FrameType::Open, stream->id, encode_open_request(req));
    {
        std::unique_lock<std::mutex> lock(stream->mutex);
        stream->cv.wait(lock, [&] {
            return stream->state == LocalStream::State::Open ||
                   stream->state == LocalStream::State::Failed ||
                   !running_;
        });
        if (stream->state != LocalStream::State::Open) {
            send_socks5_reply(sock, 0x05);
            close_stream(stream->id, false);
            return;
        }
    }

    if (!send_socks5_reply(sock, 0x00)) {
        close_stream(stream->id, true);
    }
}

void ClientRuntime::pump_local_socket(const std::shared_ptr<LocalStream>& stream) {
    std::array<std::uint8_t, 4096> buf{};
#ifdef _WIN32
    const int ret = ::recv(stream->sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
#else
    const int ret = static_cast<int>(::recv(stream->sock, buf.data(), buf.size(), 0));
#endif
    if (ret <= 0) {
        close_stream(stream->id, true);
        return;
    }
    queue_frame(FrameType::Data, stream->id,
                std::vector<std::uint8_t>(buf.begin(), buf.begin() + ret));
}

void ClientRuntime::close_stream(std::uint32_t id, bool notify_remote) {
    std::shared_ptr<LocalStream> stream;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        const auto it = streams_.find(id);
        if (it == streams_.end()) {
            return;
        }
        stream = it->second;
        streams_.erase(it);
    }
    if (notify_remote && running_) {
        queue_frame(FrameType::Close, id, {});
    }
    close_socket(stream->sock);
    {
        std::lock_guard<std::mutex> lock(stream->mutex);
        stream->state = LocalStream::State::Closed;
    }
    stream->cv.notify_all();
}

void ClientRuntime::close_all_streams() {
    std::map<std::uint32_t, std::shared_ptr<LocalStream>> current;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        current.swap(streams_);
    }
    for (auto& kv : current) {
        close_socket(kv.second->sock);
        std::lock_guard<std::mutex> lock(kv.second->mutex);
        kv.second->state = LocalStream::State::Closed;
        kv.second->cv.notify_all();
    }
}

socket_t ClientRuntime::make_listener(std::uint16_t port) {
    socket_t sock = static_cast<socket_t>(::socket(AF_INET, SOCK_STREAM, 0));
    if (sock == kInvalidSocket) {
        return kInvalidSocket;
    }
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(sock);
        return kInvalidSocket;
    }
    if (::listen(sock, 128) != 0) {
        close_socket(sock);
        return kInvalidSocket;
    }
    return sock;
}

ClientConfig parse_args(int argc, char** argv) {
    ClientConfig cfg;
    if (argc >= 2) {
        parse_host_port(argv[1], cfg.server_host, cfg.server_port);
    }
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--listen" && i + 1 < argc) {
            cfg.listen_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--auth-password" && i + 1 < argc) {
            cfg.auth_password = argv[++i];
        } else if (arg == "--ech-config" && i + 1 < argc) {
            cfg.ech_config = argv[++i];
        } else if (arg == "--disable-ech-grease") {
            cfg.enable_ech_grease = false;
        } else if (arg == "--log-level" && i + 1 < argc) {
            LogLevel level = LogLevel::Info;
            if (parse_log_level(argv[++i], level)) {
                cfg.log_level = level;
            }
        }
    }
    return cfg;
}

void print_usage() {
    std::cout
        << "用法:\n"
        << "  client <server_host:port> [--listen <port>]\n\n"
        << "说明:\n"
        << "  <server_host:port>   远端 HTTP/2 TLS 隧道服务地址\n"
        << "  --listen <port>      本地 SOCKS5 监听端口, 默认 1080\n"
        << "  --auth-password <pw> 发送到服务端 /api/tunnel/* 的预共享密码\n"
        << "  --log-level <level>  日志级别: error|warn|info|debug, 默认 info\n\n"
        << "  --ech-config <b64>   base64-encoded ECHConfigList\n"
        << "  --disable-ech-grease do not send GREASE ECH without a config list\n"
        << "行为:\n"
        << "  1. 建立 1 条长期 HTTP/2 TLS 连接\n"
        << "  2. 使用 open stream 创建隧道会话\n"
        << "  3. 使用一个长期 events stream 接收下行事件\n"
        << "  4. 使用一个或多个 upload stream 上传数据帧\n\n"
        << "示例:\n"
        << "  client 127.0.0.1:8443\n"
        << "  client 117.72.179.59:8443 --listen 1088 --auth-password secret123\n"
        << "  client example.com:8443 --ech-config <base64-ech-config-list>\n";
}

} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup 失败\n";
        return 1;
    }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        }
    }

    const ClientConfig cfg = parse_args(argc, argv);
    set_log_level(cfg.log_level);
    if (cfg.server_host.empty()) {
        print_usage();
        return 1;
    }

    ClientRuntime runtime(cfg);
    if (!runtime.start()) {
        return 1;
    }
    return 0;
}
