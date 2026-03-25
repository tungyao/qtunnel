#include "common/logging.h"
#include "common/socks5.h"
#include "common/tls_wrapper.h"
#include "common/tunnel_protocol.h"

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/socket.h>
#endif

namespace {

using proxy::close_socket;
using proxy::connect_tcp;
using proxy::decode_open_request;
using proxy::encode_open_fail;
using proxy::encode_open_ok;
using proxy::FrameHeader;
using proxy::FrameType;
using proxy::kInvalidSocket;
using proxy::parse_frames;
using proxy::parse_log_level;
using proxy::recv_exact;
using proxy::send_exact;
using proxy::set_log_level;
using proxy::select_http2_padded_length;
using proxy::socket_t;
using proxy::LogLevel;
using proxy::TlsSocket;
using proxy::to_bytes;

struct ServerConfig {
    enum class TargetType {
        Direct,
        Raw,
        Socks5
    };

    std::uint16_t listen_port = 8443;
    bool has_fixed_target = false;
    std::string fixed_host;
    std::uint16_t fixed_port = 0;
    TargetType target_type = TargetType::Direct;
    std::string cert_file;
    std::string key_file;
    std::string auth_password;
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

std::vector<HeaderField> make_response_header_fields(int status, const std::string& content_type) {
    std::vector<HeaderField> fields;
    fields.push_back({":status", std::to_string(status)});
    fields.push_back({"server", "nginx"});
    if (!content_type.empty()) {
        fields.push_back({"content-type", content_type});
    }
    return fields;
}

void append_cover_headers(std::vector<HeaderField>& fields, bool html_body) {
    fields.push_back({"cache-control", "public, max-age=300"});
    fields.push_back({"vary", "Accept-Encoding"});
    fields.push_back({"x-content-type-options", "nosniff"});
    fields.push_back({"x-frame-options", "SAMEORIGIN"});
    fields.push_back({"referrer-policy", "strict-origin-when-cross-origin"});
    if (html_body) {
        fields.push_back({"content-language", "en"});
    }
}

int ascii_casecmp(const char* lhs, const char* rhs) {
#ifdef _WIN32
    return _stricmp(lhs, rhs);
#else
    return strcasecmp(lhs, rhs);
#endif
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

std::vector<std::uint8_t> encode_socks5_target(std::uint8_t atyp, const std::string& host, std::uint16_t port) {
    std::vector<std::uint8_t> req = {0x05, 0x01, 0x00, atyp};
    if (atyp == 0x01) {
        in_addr ipv4{};
        if (::inet_pton(AF_INET, host.c_str(), &ipv4) != 1) {
            return {};
        }
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&ipv4);
        req.insert(req.end(), bytes, bytes + 4);
    } else if (atyp == 0x04) {
        in6_addr ipv6{};
        if (::inet_pton(AF_INET6, host.c_str(), &ipv6) != 1) {
            return {};
        }
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&ipv6);
        req.insert(req.end(), bytes, bytes + 16);
    } else {
        if (host.size() > 255) {
            return {};
        }
        req.push_back(static_cast<std::uint8_t>(host.size()));
        req.insert(req.end(), host.begin(), host.end());
    }
    req.push_back(static_cast<std::uint8_t>((port >> 8) & 0xff));
    req.push_back(static_cast<std::uint8_t>(port & 0xff));
    return req;
}

bool complete_socks5_connect(socket_t proxy_sock, std::uint8_t atyp, const std::string& host,
                             std::uint16_t port, std::string& error) {
    const std::uint8_t hello[3] = {0x05, 0x01, 0x00};
    if (send_exact(proxy_sock, hello, sizeof(hello)) != static_cast<int>(sizeof(hello))) {
        error = "发送 SOCKS5 上游 greeting 失败";
        return false;
    }

    std::uint8_t method_reply[2] = {};
    if (recv_exact(proxy_sock, method_reply, sizeof(method_reply)) != static_cast<int>(sizeof(method_reply))) {
        error = "读取 SOCKS5 上游 method reply 失败";
        return false;
    }
    if (method_reply[0] != 0x05 || method_reply[1] != 0x00) {
        error = "上游 SOCKS5 不支持无认证";
        return false;
    }

    const std::vector<std::uint8_t> connect_req = encode_socks5_target(atyp, host, port);
    if (connect_req.empty()) {
        error = "构造上游 SOCKS5 CONNECT 请求失败";
        return false;
    }
    if (send_exact(proxy_sock, connect_req.data(), connect_req.size()) != static_cast<int>(connect_req.size())) {
        error = "发送 SOCKS5 CONNECT 请求失败";
        return false;
    }

    std::uint8_t reply_head[4] = {};
    if (recv_exact(proxy_sock, reply_head, sizeof(reply_head)) != static_cast<int>(sizeof(reply_head))) {
        error = "读取 SOCKS5 CONNECT 响应头失败";
        return false;
    }
    if (reply_head[0] != 0x05 || reply_head[1] != 0x00) {
        error = "上游 SOCKS5 CONNECT 被拒绝, code=" + std::to_string(reply_head[1]);
        return false;
    }

    std::size_t addr_len = 0;
    if (reply_head[3] == 0x01) {
        addr_len = 4;
    } else if (reply_head[3] == 0x04) {
        addr_len = 16;
    } else if (reply_head[3] == 0x03) {
        std::uint8_t domain_len = 0;
        if (recv_exact(proxy_sock, &domain_len, sizeof(domain_len)) != static_cast<int>(sizeof(domain_len))) {
            error = "读取 SOCKS5 域名长度失败";
            return false;
        }
        addr_len = domain_len;
    } else {
        error = "上游 SOCKS5 返回了未知 ATYP";
        return false;
    }

    std::vector<std::uint8_t> discard(addr_len + 2, 0);
    if (!discard.empty() && recv_exact(proxy_sock, discard.data(), discard.size()) != static_cast<int>(discard.size())) {
        error = "读取 SOCKS5 绑定地址失败";
        return false;
    }
    return true;
}

bool open_upstream_channel(const ServerConfig& config, std::uint8_t requested_atyp,
                           const std::string& requested_host, std::uint16_t requested_port,
                           socket_t& upstream, std::string& error) {
    if (!config.has_fixed_target || config.target_type == ServerConfig::TargetType::Direct) {
        upstream = connect_tcp(requested_host, requested_port, error);
        return upstream != kInvalidSocket;
    }
    upstream = connect_tcp(config.fixed_host, config.fixed_port, error);
    if (upstream == kInvalidSocket) {
        return false;
    }
    if (config.target_type == ServerConfig::TargetType::Raw) {
        return true;
    }
    if (!complete_socks5_connect(upstream, requested_atyp, requested_host, requested_port, error)) {
        close_socket(upstream);
        upstream = kInvalidSocket;
        return false;
    }
    return true;
}

std::string homepage_html() {
    return "<!doctype html><html><head><meta charset='utf-8'><title>qtunnel</title>"
           "<style>body{font-family:Georgia,serif;max-width:760px;margin:64px auto;padding:0 16px;"
           "line-height:1.7;background:#f6f1e8;color:#1f2933}main{background:#fff;padding:32px;"
           "border-radius:18px;box-shadow:0 10px 30px rgba(31,41,51,.08)}h1{margin-top:0}</style>"
           "</head><body><main><h1>qtunnel</h1><p>This endpoint hosts a private HTTP/2 tunnel service.</p>"
           "<p>The public homepage is intentionally simple, while data transport is handled by the "
           "<code>/api/tunnel/*</code> endpoints.</p></main></body></html>";
}

struct Http1Request {
    std::string method;
    std::string path;
};

bool read_http1_request(TlsSocket& tls, Http1Request& request) {
    std::string buffer;
    std::array<std::uint8_t, 4096> chunk{};
    while (buffer.find("\r\n\r\n") == std::string::npos) {
        const int ret = tls.read(chunk.data(), chunk.size());
        if (ret <= 0) {
            return false;
        }
        buffer.append(reinterpret_cast<const char*>(chunk.data()), ret);
        if (buffer.size() > 1024 * 1024) {
            return false;
        }
    }

    const auto line_end = buffer.find("\r\n");
    if (line_end == std::string::npos) {
        return false;
    }
    const std::string request_line = buffer.substr(0, line_end);
    std::istringstream line_stream(request_line);
    std::string version;
    if (!(line_stream >> request.method >> request.path >> version)) {
        return false;
    }
    return true;
}

bool send_http1_response(TlsSocket& tls, int status, const std::string& content_type,
                         const std::vector<std::uint8_t>& body, bool homepage = false) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << (status == 200 ? " OK" : " ERROR") << "\r\n";
    oss << "Content-Type: " << content_type << "\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "Server: nginx\r\n";
    oss << "Cache-Control: public, max-age=300\r\n";
    oss << "Vary: Accept-Encoding\r\n";
    oss << "X-Content-Type-Options: nosniff\r\n";
    oss << "X-Frame-Options: SAMEORIGIN\r\n";
    oss << "Referrer-Policy: strict-origin-when-cross-origin\r\n";
    if (homepage) {
        oss << "Content-Language: en\r\n";
    }
    oss << "\r\n";
    const std::string head = oss.str();
    return tls.write_all(reinterpret_cast<const std::uint8_t*>(head.data()), head.size()) &&
           (body.empty() || tls.write_all(body.data(), body.size()));
}

class Http2ServerConnection {
public:
    Http2ServerConnection(socket_t accepted_socket, ServerConfig config)
        : accepted_socket_(accepted_socket), config_(std::move(config)) {}

    ~Http2ServerConnection();
    void run();

private:
    struct UpstreamStream {
        std::uint32_t id = 0;
        socket_t sock = kInvalidSocket;
    };

    struct RequestState {
        enum class ResponseMode {
            None,
            StaticBody,
            EventStream
        };

        std::string method;
        std::string path;
        std::map<std::string, std::string> headers;
        std::vector<std::uint8_t> body;
        ResponseMode response_mode = ResponseMode::None;
        std::vector<std::uint8_t> response_body;
        std::size_t response_offset = 0;
    };

    bool initialize();
    void handle_http1_connection();
    bool flush_session();
    void loop();
    void handle_request(int32_t stream_id);
    void submit_static_response(int32_t stream_id, int status, const std::string& content_type,
                                const std::vector<std::uint8_t>& body);
    void enqueue_downlink(FrameType type, std::uint32_t stream_id, const std::vector<std::uint8_t>& payload);
    void close_logical_stream(std::uint32_t stream_id, bool notify_client);
    void close_all_upstreams();
    std::string get_header_value_ci(const RequestState& request, const std::string& name) const;
    bool is_authorized(const RequestState& request) const;

    static nghttp2_ssize read_response_body(nghttp2_session* session, int32_t stream_id, uint8_t* buf,
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

    socket_t accepted_socket_ = kInvalidSocket;
    ServerConfig config_;
    TlsSocket tls_;
    nghttp2_session* h2_ = nullptr;
    std::map<int32_t, RequestState> requests_;
    std::map<std::uint32_t, UpstreamStream> streams_;
    std::vector<std::uint8_t> downlink_;
    std::size_t downlink_offset_ = 0;
    int32_t event_stream_id_ = -1;
    bool tunnel_opened_ = false;
    bool running_ = true;
};

Http2ServerConnection::~Http2ServerConnection() {
    close_all_upstreams();
    if (h2_ != nullptr) {
        nghttp2_session_del(h2_);
        h2_ = nullptr;
    }
    tls_.shutdown();
    close_socket(accepted_socket_);
}

void Http2ServerConnection::run() {
    if (!tls_.accept_server(accepted_socket_, config_.cert_file, config_.key_file)) {
        PROXY_LOG(Error, "[server] TLS 握手失败: " << tls_.last_error());
        return;
    }
    PROXY_LOG(Debug, "[server] TLS version: " << tls_.negotiated_tls_version());
    PROXY_LOG(Debug, "[server] TLS cipher: " << tls_.negotiated_cipher());
    PROXY_LOG(Debug, "[server] TLS ALPN: "
                          << (tls_.negotiated_alpn().empty() ? "<none>" : tls_.negotiated_alpn()));
    PROXY_LOG(Debug, "[server] TLS SNI: "
                          << (tls_.requested_server_name().empty() ? "<none>" : tls_.requested_server_name()));
    if (tls_.negotiated_alpn() != "h2") {
        handle_http1_connection();
        return;
    }
    if (!initialize()) {
        return;
    }
    loop();
}

bool Http2ServerConnection::initialize() {
    nghttp2_session_callbacks* callbacks = nullptr;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &Http2ServerConnection::on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, &Http2ServerConnection::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &Http2ServerConnection::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &Http2ServerConnection::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &Http2ServerConnection::on_stream_close);
    nghttp2_session_callbacks_set_select_padding_callback2(callbacks, &Http2ServerConnection::select_padding);

    if (nghttp2_session_server_new(&h2_, callbacks, this) != 0) {
        nghttp2_session_callbacks_del(callbacks);
        PROXY_LOG(Error, "[server] nghttp2_session_server_new 失败");
        return false;
    }
    nghttp2_session_callbacks_del(callbacks);

    if (nghttp2_submit_settings(h2_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0 || !flush_session()) {
        PROXY_LOG(Error, "[server] 发送 HTTP/2 SETTINGS 失败");
        return false;
    }
    return true;
}

void Http2ServerConnection::handle_http1_connection() {
    Http1Request request;
    if (!read_http1_request(tls_, request)) {
        return;
    }
    if (request.method == "GET" && request.path == "/") {
        send_http1_response(tls_, 200, "text/html; charset=utf-8", to_bytes(homepage_html()), true);
    } else {
        send_http1_response(tls_, 404, "text/plain", to_bytes("not found"));
    }
}

bool Http2ServerConnection::flush_session() {
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

void Http2ServerConnection::loop() {
    while (running_) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tls_.raw_socket(), &readfds);
        socket_t maxfd = tls_.raw_socket();

        for (const auto& kv : streams_) {
            FD_SET(kv.second.sock, &readfds);
            if (kv.second.sock > maxfd) {
                maxfd = kv.second.sock;
            }
        }

        if (!downlink_.empty() && event_stream_id_ >= 0) {
            nghttp2_session_resume_data(h2_, event_stream_id_);
            if (!flush_session()) {
                running_ = false;
                break;
            }
        }

        timeval tv{};
        tv.tv_usec = 100000;
        const int ready = ::select(static_cast<int>(maxfd + 1), &readfds, nullptr, nullptr, &tv);
        if (ready < 0) {
            continue;
        }

        if (ready > 0 && FD_ISSET(tls_.raw_socket(), &readfds)) {
            std::array<std::uint8_t, 16384> buf{};
            const int ret = tls_.read(buf.data(), buf.size());
            if (ret <= 0) {
                break;
            }
            const auto consumed = nghttp2_session_mem_recv2(h2_, buf.data(), static_cast<size_t>(ret));
            if (consumed < 0) {
                PROXY_LOG(Error, "[server] nghttp2_session_mem_recv2 失败: "
                                    << nghttp2_strerror(static_cast<int>(consumed)));
                break;
            }
            if (!flush_session()) {
                break;
            }
        }

        std::vector<std::uint32_t> to_close;
        for (const auto& kv : streams_) {
            if (!FD_ISSET(kv.second.sock, &readfds)) {
                continue;
            }
            std::array<std::uint8_t, 4096> buf{};
#ifdef _WIN32
            const int ret = ::recv(kv.second.sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
#else
            const int ret = static_cast<int>(::recv(kv.second.sock, buf.data(), buf.size(), 0));
#endif
            if (ret <= 0) {
                to_close.push_back(kv.first);
                continue;
            }
            enqueue_downlink(FrameType::Data, kv.first,
                             std::vector<std::uint8_t>(buf.begin(), buf.begin() + ret));
        }
        for (const auto stream_id : to_close) {
            close_logical_stream(stream_id, true);
        }
    }
}

void Http2ServerConnection::submit_static_response(int32_t stream_id, int status, const std::string& content_type,
                                                   const std::vector<std::uint8_t>& body) {
    PROXY_LOG(Debug, "[server] response stream=" << stream_id << " status=" << status
                                                 << " body=" << body.size() << " bytes");
    auto& request = requests_[stream_id];
    request.response_mode = RequestState::ResponseMode::StaticBody;
    request.response_body = body;
    request.response_offset = 0;

    auto header_fields = make_response_header_fields(status, content_type);
    if (status == 200 && content_type.find("text/html") != std::string::npos) {
        append_cover_headers(header_fields, true);
    }
    std::vector<nghttp2_nv> headers;
    headers.reserve(header_fields.size());
    for (const auto& field : header_fields) {
        headers.push_back(make_nv(field.name, field.value));
    }
    nghttp2_data_provider2 provider{};
    nghttp2_data_provider2* provider_ptr = nullptr;
    if (!body.empty()) {
        provider.source.ptr = &request;
        provider.read_callback = &Http2ServerConnection::read_response_body;
        provider_ptr = &provider;
    }
    nghttp2_submit_response2(h2_, stream_id, headers.data(), headers.size(), provider_ptr);
    flush_session();
}

void Http2ServerConnection::enqueue_downlink(FrameType type, std::uint32_t stream_id,
                                             const std::vector<std::uint8_t>& payload) {
    proxy::append_frame(downlink_, type, stream_id, payload);
    if (event_stream_id_ >= 0) {
        nghttp2_session_resume_data(h2_, event_stream_id_);
    }
}

void Http2ServerConnection::close_logical_stream(std::uint32_t stream_id, bool notify_client) {
    const auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return;
    }
    close_socket(it->second.sock);
    streams_.erase(it);
    if (notify_client) {
        enqueue_downlink(FrameType::Close, stream_id, {});
    }
}

void Http2ServerConnection::close_all_upstreams() {
    for (auto& kv : streams_) {
        close_socket(kv.second.sock);
    }
    streams_.clear();
}

std::string Http2ServerConnection::get_header_value_ci(const RequestState& request, const std::string& name) const {
    for (const auto& kv : request.headers) {
        if (ascii_casecmp(kv.first.c_str(), name.c_str()) == 0) {
            return kv.second;
        }
    }
    return {};
}

bool Http2ServerConnection::is_authorized(const RequestState& request) const {
    if (config_.auth_password.empty()) {
        return true;
    }
    if (request.path.rfind("/api/tunnel/", 0) != 0) {
        return true;
    }
    return get_header_value_ci(request, "x-tunnel-auth") == config_.auth_password;
}

void Http2ServerConnection::handle_request(int32_t stream_id) {
    auto it = requests_.find(stream_id);
    if (it == requests_.end()) {
        return;
    }
    auto& request = it->second;
    PROXY_LOG(Debug, "[server] request stream=" << stream_id
                                                << " method=" << request.method
                                                << " path=" << request.path
                                                << " body=" << request.body.size() << " bytes");

    if (!is_authorized(request)) {
        submit_static_response(stream_id, 403, "text/plain", to_bytes("forbidden"));
        return;
    }

    if (request.method == "GET" && request.path == "/") {
        submit_static_response(stream_id, 200, "text/html; charset=utf-8", to_bytes(homepage_html()));
        return;
    }

    if (request.method == "POST" && request.path == "/api/tunnel/open") {
        if (tunnel_opened_) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("tunnel already opened"));
            return;
        }
        tunnel_opened_ = true;
        submit_static_response(stream_id, 200, "text/plain", to_bytes("ok"));
        return;
    }

    if (request.method == "GET" && request.path == "/api/tunnel/events") {
        if (!tunnel_opened_) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("open stream required first"));
            return;
        }
        if (event_stream_id_ >= 0) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("event stream already exists"));
            return;
        }

        request.response_mode = RequestState::ResponseMode::EventStream;
        request.response_offset = 0;
        event_stream_id_ = stream_id;

        const auto header_fields = make_response_header_fields(200, "application/octet-stream");
        std::vector<nghttp2_nv> headers;
        headers.reserve(header_fields.size());
        for (const auto& field : header_fields) {
            headers.push_back(make_nv(field.name, field.value));
        }
        nghttp2_data_provider2 provider{};
        provider.source.ptr = &request;
        provider.read_callback = &Http2ServerConnection::read_response_body;
        nghttp2_submit_response2(h2_, stream_id, headers.data(), headers.size(), &provider);
        flush_session();
        return;
    }

    if (request.method == "POST" && request.path == "/api/tunnel/upload") {
        if (!tunnel_opened_) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("open stream required first"));
            return;
        }

        std::vector<std::pair<FrameHeader, std::vector<std::uint8_t>>> frames;
        if (!parse_frames(request.body, frames)) {
            submit_static_response(stream_id, 400, "text/plain", to_bytes("bad frame body"));
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
                    enqueue_downlink(FrameType::OpenFail, tunnel_stream_id, encode_open_fail("bad open request"));
                    continue;
                }

                std::string error;
                socket_t upstream = kInvalidSocket;
                if (!open_upstream_channel(config_, atyp, requested_host, requested_port, upstream, error)) {
                    enqueue_downlink(FrameType::OpenFail, tunnel_stream_id, encode_open_fail(error));
                    continue;
                }

                streams_[tunnel_stream_id] = UpstreamStream{tunnel_stream_id, upstream};
                enqueue_downlink(FrameType::OpenOk, tunnel_stream_id, encode_open_ok());
            } else if (type == FrameType::Data) {
                const auto stream_it = streams_.find(tunnel_stream_id);
                if (stream_it == streams_.end()) {
                    continue;
                }
#ifdef _WIN32
                const int ret = ::send(stream_it->second.sock, reinterpret_cast<const char*>(item.second.data()),
                                       static_cast<int>(item.second.size()), 0);
#else
                const int ret = static_cast<int>(::send(stream_it->second.sock, item.second.data(),
                                                        item.second.size(), 0));
#endif
                if (ret <= 0) {
                    close_logical_stream(tunnel_stream_id, true);
                }
            } else if (type == FrameType::Close) {
                close_logical_stream(tunnel_stream_id, false);
            } else if (type == FrameType::Ping) {
                enqueue_downlink(FrameType::Pong, 0, item.second);
            }
        }

        submit_static_response(stream_id, 200, "text/plain", to_bytes("ok"));
        return;
    }

    if (request.method == "POST" && request.path == "/api/tunnel/close") {
        submit_static_response(stream_id, 200, "text/plain", to_bytes("closed"));
        running_ = false;
        return;
    }

    submit_static_response(stream_id, 404, "text/plain", to_bytes("not found"));
}

nghttp2_ssize Http2ServerConnection::read_response_body(nghttp2_session* /*session*/, int32_t /*stream_id*/, uint8_t* buf,
                                                        size_t length, uint32_t* data_flags, nghttp2_data_source* source,
                                                        void* user_data) {
    auto* self = static_cast<Http2ServerConnection*>(user_data);
    auto* request = static_cast<RequestState*>(source->ptr);
    if (request->response_mode == RequestState::ResponseMode::EventStream) {
        const std::size_t available = self->downlink_.size() - self->downlink_offset_;
        if (available == 0) {
            if (!self->running_) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                return 0;
            }
            return NGHTTP2_ERR_DEFERRED;
        }
        const std::size_t copy_len = available < length ? available : length;
        std::memcpy(buf, self->downlink_.data() + self->downlink_offset_, copy_len);
        self->downlink_offset_ += copy_len;
        if (self->downlink_offset_ >= self->downlink_.size()) {
            self->downlink_.clear();
            self->downlink_offset_ = 0;
            if (!self->running_) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
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
    if (request->response_offset >= request->response_body.size()) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return static_cast<nghttp2_ssize>(copy_len);
}

int Http2ServerConnection::on_begin_headers(nghttp2_session* /*session*/, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<Http2ServerConnection*>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        PROXY_LOG(Debug, "[server] begin headers stream=" << frame->hd.stream_id);
        self->requests_[frame->hd.stream_id] = RequestState{};
    }
    return 0;
}

int Http2ServerConnection::on_header(nghttp2_session* /*session*/, const nghttp2_frame* frame, const uint8_t* name,
                                     size_t namelen, const uint8_t* value, size_t valuelen, uint8_t /*flags*/,
                                     void* user_data) {
    auto* self = static_cast<Http2ServerConnection*>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    auto it = self->requests_.find(frame->hd.stream_id);
    if (it == self->requests_.end()) {
        return 0;
    }

    const std::string header_name(reinterpret_cast<const char*>(name), namelen);
    const std::string header_value(reinterpret_cast<const char*>(value), valuelen);
    PROXY_LOG(Debug, "[server] header stream=" << frame->hd.stream_id << " "
                                               << header_name << "=" << header_value);
    if (header_name == ":method") {
        it->second.method = header_value;
    } else if (header_name == ":path") {
        it->second.path = header_value;
    } else {
        it->second.headers[header_name] = header_value;
    }
    return 0;
}

int Http2ServerConnection::on_data_chunk_recv(nghttp2_session* /*session*/, uint8_t /*flags*/, int32_t stream_id,
                                              const uint8_t* data, size_t len, void* user_data) {
    auto* self = static_cast<Http2ServerConnection*>(user_data);
    auto it = self->requests_.find(stream_id);
    if (it == self->requests_.end()) {
        return 0;
    }
    it->second.body.insert(it->second.body.end(), data, data + len);
    return 0;
}

int Http2ServerConnection::on_frame_recv(nghttp2_session* /*session*/, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<Http2ServerConnection*>(user_data);
    if ((frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) ||
        frame->hd.type == NGHTTP2_DATA) {
        if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
            self->handle_request(frame->hd.stream_id);
        }
    }
    return 0;
}

int Http2ServerConnection::on_stream_close(nghttp2_session* /*session*/, int32_t stream_id, uint32_t /*error_code*/,
                                           void* user_data) {
    auto* self = static_cast<Http2ServerConnection*>(user_data);
    self->requests_.erase(stream_id);
    if (stream_id == self->event_stream_id_) {
        self->event_stream_id_ = -1;
    }
    return 0;
}

nghttp2_ssize Http2ServerConnection::select_padding(nghttp2_session* /*session*/, const nghttp2_frame* frame,
                                                    size_t max_payloadlen, void* /*user_data*/) {
    return static_cast<nghttp2_ssize>(
        select_http2_padded_length(frame->hd.type, frame->hd.length, max_payloadlen));
}

socket_t make_listener(std::uint16_t port) {
    socket_t sock = static_cast<socket_t>(::socket(AF_INET6, SOCK_STREAM, 0));
    if (sock == kInvalidSocket) {
        return kInvalidSocket;
    }
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
#ifdef IPV6_V6ONLY
    int no = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&no), sizeof(no));
#endif
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);
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

ServerConfig parse_args(int argc, char** argv) {
    ServerConfig cfg;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--listen" && i + 1 < argc) {
            cfg.listen_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--cert-file" && i + 1 < argc) {
            cfg.cert_file = argv[++i];
        } else if (arg == "--key-file" && i + 1 < argc) {
            cfg.key_file = argv[++i];
        } else if (arg == "--auth-password" && i + 1 < argc) {
            cfg.auth_password = argv[++i];
        } else if (arg == "--log-level" && i + 1 < argc) {
            LogLevel level = LogLevel::Info;
            if (parse_log_level(argv[++i], level)) {
                cfg.log_level = level;
            }
        } else if (arg == "--target" && i + 1 < argc) {
            cfg.has_fixed_target = parse_host_port(argv[++i], cfg.fixed_host, cfg.fixed_port);
            if (cfg.has_fixed_target) {
                cfg.target_type = ServerConfig::TargetType::Socks5;
            }
        } else if (arg == "--target-type" && i + 1 < argc) {
            const std::string type = argv[++i];
            if (type == "raw") {
                cfg.target_type = ServerConfig::TargetType::Raw;
            } else if (type == "socks5") {
                cfg.target_type = ServerConfig::TargetType::Socks5;
            } else if (type == "direct") {
                cfg.target_type = ServerConfig::TargetType::Direct;
            }
        } else if (!arg.empty() && arg[0] != '-') {
            cfg.has_fixed_target = parse_host_port(arg, cfg.fixed_host, cfg.fixed_port);
            if (cfg.has_fixed_target) {
                cfg.target_type = ServerConfig::TargetType::Socks5;
            }
        }
    }
    return cfg;
}

void print_usage() {
    std::cout
        << "用法:\n"
        << "  server [--listen <port>] [--cert-file <cert.pem>] [--key-file <key.pem>] "
           "[--target <host:port>] [--target-type direct|socks5|raw]\n"
        << "  server <host:port>\n\n"
        << "说明:\n"
        << "  --listen <port>        HTTP/2 TLS 监听端口, 默认 8443\n"
        << "  --cert-file <path>     加载正式 PEM 证书文件\n"
        << "  --key-file <path>      加载正式 PEM 私钥文件\n"
        << "  --auth-password <pw>   为 /api/tunnel/* 设置预共享密码\n"
        << "  --log-level <level>    日志级别: error|warn|info|debug, 默认 info\n"
        << "  --target <host:port>   指定固定上游地址\n"
        << "  --target-type direct   忽略 --target, 直接连接客户端请求目标\n"
        << "  --target-type socks5   把 --target 当作上游 SOCKS5 代理, 默认值\n"
        << "  --target-type raw      把 --target 当作固定最终 TCP 目标, 不做代理协商\n\n"
        << "HTTP/2 stream 模型:\n"
        << "  POST /api/tunnel/open    创建隧道\n"
        << "  GET  /api/tunnel/events  长期下行事件流\n"
        << "  POST /api/tunnel/upload  一个或多个上传流\n"
        << "  POST /api/tunnel/close   关闭隧道\n\n"
        << "示例:\n"
        << "  server --listen 8443\n"
        << "  server --listen 8443 --auth-password secret123\n"
        << "  server --listen 8443 --cert-file fullchain.pem --key-file privkey.pem\n"
        << "  server --listen 8443 --target 127.0.0.1:1080\n"
        << "  server --listen 8443 --target 8.8.8.8:443 --target-type raw\n";
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

    const ServerConfig config = parse_args(argc, argv);
    set_log_level(config.log_level);
    socket_t listener = make_listener(config.listen_port);
    if (listener == kInvalidSocket) {
        std::cerr << "创建监听 socket 失败\n";
        return 1;
    }

    PROXY_LOG(Info, "server 监听 0.0.0.0/[::]:" << config.listen_port);
    if (config.has_fixed_target) {
        std::ostringstream target_desc;
        target_desc << "固定上游目标: " << config.fixed_host << ":" << config.fixed_port;
        if (config.target_type == ServerConfig::TargetType::Raw) {
            target_desc << " (raw)";
        } else if (config.target_type == ServerConfig::TargetType::Socks5) {
            target_desc << " (socks5)";
        } else {
            target_desc << " (direct)";
        }
        PROXY_LOG(Info, target_desc.str());
    } else {
        PROXY_LOG(Info, "按客户端请求直连目标");
    }

    while (true) {
        sockaddr_storage ss{};
        socklen_t slen = sizeof(ss);
        socket_t client = ::accept(listener, reinterpret_cast<sockaddr*>(&ss), &slen);
        if (client == kInvalidSocket) {
            continue;
        }
        std::thread([client, config]() mutable {
            Http2ServerConnection connection(client, config);
            connection.run();
        }).detach();
    }

    return 0;
}
