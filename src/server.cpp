#include "common/logging.h"
#include "common/socks5.h"
#include "common/tls_wrapper.h"
#include "common/tunnel_protocol.h"
#include "homepage_html.h"

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
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

constexpr std::size_t kTunnelIoChunkSize = 256 * 1024;
constexpr std::size_t kSessionFlushBudgetBytes = 256 * 1024;
constexpr std::int32_t kHttp2WindowSize = 16 * 1024 * 1024;
constexpr std::uint32_t kHttp2MaxFrameSize = 1024 * 1024;

using proxy::close_socket;
using proxy::connect_tcp;
using proxy::decode_open_request;
using proxy::encode_open_fail;
using proxy::encode_open_ok;
using proxy::EventDispatcher;
using proxy::EventNotifier;
using proxy::FrameHeader;
using proxy::FrameType;
using proxy::kInvalidSocket;
using proxy::parse_log_level;
using proxy::recv_exact;
using proxy::send_exact;
using proxy::set_log_level;
using proxy::set_socket_nonblocking;
using proxy::select_http2_padded_length;
using proxy::SocketEvent;
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

bool is_socket_would_block(int code) {
#ifdef _WIN32
    return code == WSAEWOULDBLOCK;
#else
    return code == EAGAIN || code == EWOULDBLOCK;
#endif
}

void signal_notifier(EventNotifier& notifier, const char* owner, const char* action) {
    std::string error;
    if (!notifier.signal(error) && !error.empty()) {
        PROXY_LOG(Debug, "[" << owner << "] " << action << " 唤醒失败: " << error);
    }
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
        if (upstream == kInvalidSocket) {
            return false;
        }
    } else {
        upstream = connect_tcp(config.fixed_host, config.fixed_port, error);
        if (upstream == kInvalidSocket) {
            return false;
        }
        if (config.target_type != ServerConfig::TargetType::Raw &&
            !complete_socks5_connect(upstream, requested_atyp, requested_host, requested_port, error)) {
            close_socket(upstream);
            upstream = kInvalidSocket;
            return false;
        }
    }

    std::string nonblocking_error;
    if (!set_socket_nonblocking(upstream, true, nonblocking_error)) {
        error = nonblocking_error;
        close_socket(upstream);
        upstream = kInvalidSocket;
        return false;
    }
    return true;
}

std::string describe_upstream_route(const ServerConfig& config, const std::string& requested_host,
                                    std::uint16_t requested_port) {
    if (!config.has_fixed_target || config.target_type == ServerConfig::TargetType::Direct) {
        return requested_host + ":" + std::to_string(requested_port) + " (direct)";
    }
    if (config.target_type == ServerConfig::TargetType::Raw) {
        return config.fixed_host + ":" + std::to_string(config.fixed_port) + " (raw fixed)";
    }
    return config.fixed_host + ":" + std::to_string(config.fixed_port) + " (socks5 for " +
           requested_host + ":" + std::to_string(requested_port) + ")";
}

const char* socks5_atyp_name(std::uint8_t atyp) {
    switch (atyp) {
        case 0x01:
            return "ipv4";
        case 0x03:
            return "domain";
        case 0x04:
            return "ipv6";
        default:
            return "unknown";
    }
}

std::string homepage_html() {
    return generated::kHomepageHtml;
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
        std::vector<std::uint8_t> pending_uplink;
        std::size_t pending_uplink_offset = 0;
    };

    struct DownlinkFrame {
        FrameType type = FrameType::Data;
        std::uint32_t stream_id = 0;
        std::vector<std::uint8_t> encoded;
        std::size_t offset = 0;
    };

    struct PendingConnectResult {
        std::uint32_t stream_id = 0;
        socket_t sock = kInvalidSocket;
        std::string requested_host;
        std::uint16_t requested_port = 0;
        std::string error;
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
        bool response_started = false;
    };

    bool initialize();
    void handle_http1_connection();
    bool flush_session();
    bool flush_session_budgeted(std::size_t budget_bytes);
    bool flush_upstream_socket(UpstreamStream& stream, std::string& error);
    void start_upstream_connect(std::uint32_t stream_id, std::uint8_t atyp,
                                const std::string& requested_host, std::uint16_t requested_port);
    void process_pending_connect_results();
    void join_connector_threads();
    bool has_pending_downlink_data() const;
    DownlinkFrame* current_downlink_data_frame();
    void loop();
    void handle_request(int32_t stream_id);
    void handle_upload_frames(RequestState& request);
    void submit_static_response(int32_t stream_id, int status, const std::string& content_type,
                                const std::vector<std::uint8_t>& body);
    void enqueue_downlink(FrameType type, std::uint32_t stream_id, const std::vector<std::uint8_t>& payload);
    void purge_downlink_data_for_stream(std::uint32_t stream_id);
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
    std::deque<DownlinkFrame> downlink_control_;
    std::map<std::uint32_t, std::deque<DownlinkFrame>> downlink_data_by_stream_;
    std::deque<std::uint32_t> downlink_data_round_robin_;
    std::mutex pending_connects_mutex_;
    std::deque<PendingConnectResult> pending_connect_results_;
    std::set<std::uint32_t> connecting_streams_;
    std::vector<std::thread> connector_threads_;
    int32_t event_stream_id_ = -1;
    bool tunnel_opened_ = false;
    bool running_ = true;
    EventNotifier loop_notifier_;
};

Http2ServerConnection::~Http2ServerConnection() {
    close_all_upstreams();
    join_connector_threads();
    loop_notifier_.close();
    if (h2_ != nullptr) {
        nghttp2_session_del(h2_);
        h2_ = nullptr;
    }
    tls_.shutdown();
    close_socket(accepted_socket_);
}

void Http2ServerConnection::run() {
    std::string notifier_error;
    if (!loop_notifier_.open(notifier_error)) {
        PROXY_LOG(Error, "[server] 初始化事件唤醒器失败: " << notifier_error);
        return;
    }
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

    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, static_cast<uint32_t>(kHttp2WindowSize)},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, kHttp2MaxFrameSize},
    };
    if (nghttp2_submit_settings(h2_, NGHTTP2_FLAG_NONE, settings, 2) != 0 ||
        nghttp2_session_set_local_window_size(h2_, NGHTTP2_FLAG_NONE, 0, kHttp2WindowSize) != 0 ||
        !flush_session()) {
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

bool Http2ServerConnection::flush_session_budgeted(std::size_t budget_bytes) {
    std::size_t sent = 0;
    while (sent < budget_bytes) {
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
        sent += static_cast<std::size_t>(len);
    }
    return true;
}

bool Http2ServerConnection::flush_upstream_socket(UpstreamStream& stream, std::string& error) {
    while (stream.pending_uplink_offset < stream.pending_uplink.size()) {
        const auto* data = stream.pending_uplink.data() + stream.pending_uplink_offset;
        const std::size_t remaining = stream.pending_uplink.size() - stream.pending_uplink_offset;
#ifdef _WIN32
        const int ret = ::send(stream.sock, reinterpret_cast<const char*>(data), static_cast<int>(remaining), 0);
#else
        const int ret = static_cast<int>(::send(stream.sock, data, remaining, 0));
#endif
        if (ret > 0) {
            stream.pending_uplink_offset += static_cast<std::size_t>(ret);
            continue;
        }

        const int code = proxy::last_socket_error_code();
        if (ret < 0 && is_socket_would_block(code)) {
            break;
        }

        error = "上游 socket send 失败: " + proxy::socket_error_string();
        return false;
    }

    if (stream.pending_uplink_offset >= stream.pending_uplink.size()) {
        stream.pending_uplink.clear();
        stream.pending_uplink_offset = 0;
    } else if (stream.pending_uplink_offset >= kTunnelIoChunkSize) {
        stream.pending_uplink.erase(
            stream.pending_uplink.begin(),
            stream.pending_uplink.begin() + static_cast<std::ptrdiff_t>(stream.pending_uplink_offset));
        stream.pending_uplink_offset = 0;
    }

    return true;
}

void Http2ServerConnection::start_upstream_connect(std::uint32_t stream_id, std::uint8_t atyp,
                                                   const std::string& requested_host, std::uint16_t requested_port) {
    const ServerConfig config = config_;
    connecting_streams_.insert(stream_id);
    connector_threads_.emplace_back([this, config, stream_id, atyp, requested_host, requested_port]() {
        PendingConnectResult result;
        result.stream_id = stream_id;
        result.requested_host = requested_host;
        result.requested_port = requested_port;
        result.sock = kInvalidSocket;
        if (!open_upstream_channel(config, atyp, requested_host, requested_port, result.sock, result.error)) {
            result.sock = kInvalidSocket;
        }

        {
            std::lock_guard<std::mutex> lock(pending_connects_mutex_);
            pending_connect_results_.push_back(std::move(result));
        }
        signal_notifier(loop_notifier_, "server", "connect-result");
    });
}

void Http2ServerConnection::process_pending_connect_results() {
    std::deque<PendingConnectResult> completed;
    {
        std::lock_guard<std::mutex> lock(pending_connects_mutex_);
        completed.swap(pending_connect_results_);
    }

    for (auto& result : completed) {
        const auto connecting_it = connecting_streams_.find(result.stream_id);
        if (connecting_it == connecting_streams_.end()) {
            if (result.sock != kInvalidSocket) {
                close_socket(result.sock);
            }
            continue;
        }
        connecting_streams_.erase(connecting_it);

        if (result.sock == kInvalidSocket) {
            PROXY_LOG(Warn, "[server] Open 失败 stream=" << result.stream_id
                                                         << " requested=" << result.requested_host << ":"
                                                         << result.requested_port
                                                         << " error=" << result.error);
            enqueue_downlink(FrameType::OpenFail, result.stream_id, encode_open_fail(result.error));
            continue;
        }

        streams_[result.stream_id] = UpstreamStream{result.stream_id, result.sock};
        PROXY_LOG(Info, "[server] Open 成功 stream=" << result.stream_id
                                                     << " requested=" << result.requested_host << ":"
                                                     << result.requested_port);
        enqueue_downlink(FrameType::OpenOk, result.stream_id, encode_open_ok());
    }
}

void Http2ServerConnection::join_connector_threads() {
    for (auto& thread : connector_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    connector_threads_.clear();
}

bool Http2ServerConnection::has_pending_downlink_data() const {
    return !downlink_data_round_robin_.empty();
}

Http2ServerConnection::DownlinkFrame* Http2ServerConnection::current_downlink_data_frame() {
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

void Http2ServerConnection::loop() {
    EventDispatcher dispatcher;
    if (!dispatcher.valid()) {
        PROXY_LOG(Error, "[server] 初始化事件分发器失败");
        running_ = false;
        return;
    }
    std::map<socket_t, std::pair<bool, bool>> watched;
    while (running_) {
        process_pending_connect_results();
        std::map<socket_t, std::pair<bool, bool>> desired;
        desired[tls_.raw_socket()] = {true, false};
        desired[loop_notifier_.readable_socket()] = {true, false};
        for (const auto& kv : streams_) {
            desired[kv.second.sock] = {true, kv.second.pending_uplink_offset < kv.second.pending_uplink.size()};
        }

        if ((!downlink_control_.empty() || has_pending_downlink_data()) && event_stream_id_ >= 0) {
            nghttp2_session_resume_data(h2_, event_stream_id_);
            if (!flush_session_budgeted(kSessionFlushBudgetBytes)) {
                running_ = false;
                break;
            }
            if (!downlink_control_.empty() || has_pending_downlink_data()) {
                signal_notifier(loop_notifier_, "server", "downlink-continue");
            }
        }

        std::string dispatcher_error;
        for (auto it = watched.begin(); it != watched.end();) {
            if (desired.find(it->first) == desired.end()) {
                dispatcher.remove(it->first, dispatcher_error);
                it = watched.erase(it);
                continue;
            }
            ++it;
        }
        for (const auto& kv : desired) {
            const auto it = watched.find(kv.first);
            if (it == watched.end() || it->second != kv.second) {
                if (!dispatcher.set(kv.first, kv.second.first, kv.second.second, dispatcher_error)) {
                    PROXY_LOG(Error, "[server] 更新事件关注失败: " << dispatcher_error);
                    running_ = false;
                    break;
                }
                watched[kv.first] = kv.second;
            }
        }
        if (!running_) {
            break;
        }

        std::vector<SocketEvent> events;
        const int ready = dispatcher.wait(events, -1, dispatcher_error);
        if (ready < 0) {
            PROXY_LOG(Error, "[server] 等待事件失败: " << dispatcher_error);
            running_ = false;
            break;
        }

        std::vector<std::uint32_t> to_close;
        for (const auto& event : events) {
            if (event.sock == loop_notifier_.readable_socket()) {
                loop_notifier_.drain();
                process_pending_connect_results();
                continue;
            }

            if (event.sock == tls_.raw_socket()) {
                if (!event.readable && !event.error && !event.hangup) {
                    continue;
                }
                std::array<std::uint8_t, kTunnelIoChunkSize> buf{};
                const int ret = tls_.read(buf.data(), buf.size());
                if (ret <= 0) {
                    running_ = false;
                    break;
                }
                const auto consumed = nghttp2_session_mem_recv2(h2_, buf.data(), static_cast<size_t>(ret));
                if (consumed < 0) {
                    PROXY_LOG(Error, "[server] nghttp2_session_mem_recv2 失败: "
                                        << nghttp2_strerror(static_cast<int>(consumed)));
                    running_ = false;
                    break;
                }
                if (!flush_session()) {
                    running_ = false;
                    break;
                }
                continue;
            }

            auto stream_it = std::find_if(streams_.begin(), streams_.end(), [&](const auto& item) {
                return item.second.sock == event.sock;
            });
            if (stream_it == streams_.end()) {
                continue;
            }

            auto& stream = stream_it->second;
            if ((event.error || event.hangup) && !event.readable && !event.writable) {
                to_close.push_back(stream_it->first);
                continue;
            }
            if (event.writable) {
                std::string error;
                if (!flush_upstream_socket(stream, error)) {
                    PROXY_LOG(Debug, "[server] 上游刷新失败 stream=" << stream.id << " error=" << error);
                    to_close.push_back(stream_it->first);
                    continue;
                }
            }
            if (!event.readable) {
                continue;
            }
            std::array<std::uint8_t, kTunnelIoChunkSize> buf{};
#ifdef _WIN32
            const int ret = ::recv(stream.sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
#else
            const int ret = static_cast<int>(::recv(stream.sock, buf.data(), buf.size(), 0));
#endif
            if (ret < 0 && is_socket_would_block(proxy::last_socket_error_code())) {
                continue;
            }
            if (ret <= 0) {
                to_close.push_back(stream_it->first);
                continue;
            }
            enqueue_downlink(FrameType::Data, stream_it->first,
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
    request.response_started = true;

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
    DownlinkFrame frame;
    frame.type = type;
    frame.stream_id = stream_id;
    proxy::append_frame(frame.encoded, type, stream_id, payload);
    if (type == FrameType::Data) {
        auto& stream_queue = downlink_data_by_stream_[stream_id];
        if (stream_queue.empty()) {
            downlink_data_round_robin_.push_back(stream_id);
        }
        stream_queue.push_back(std::move(frame));
    } else {
        downlink_control_.push_back(std::move(frame));
    }
    if (event_stream_id_ >= 0) {
        nghttp2_session_resume_data(h2_, event_stream_id_);
    }
    signal_notifier(loop_notifier_, "server", "downlink");
}

void Http2ServerConnection::purge_downlink_data_for_stream(std::uint32_t stream_id) {
    std::size_t dropped_frames = 0;
    std::size_t dropped_bytes = 0;
    const auto it = downlink_data_by_stream_.find(stream_id);
    if (it != downlink_data_by_stream_.end()) {
        for (const auto& frame : it->second) {
            ++dropped_frames;
            if (frame.encoded.size() > frame.offset) {
                dropped_bytes += frame.encoded.size() - frame.offset;
            }
        }
        downlink_data_by_stream_.erase(it);
    }
    for (auto rr_it = downlink_data_round_robin_.begin(); rr_it != downlink_data_round_robin_.end();) {
        if (*rr_it == stream_id) {
            rr_it = downlink_data_round_robin_.erase(rr_it);
            continue;
        }
        ++rr_it;
    }

    if (dropped_frames > 0) {
        PROXY_LOG(Debug, "[server] 清理已关闭流的下行残留 stream=" << stream_id
                                                                    << " frames=" << dropped_frames
                                                                    << " bytes=" << dropped_bytes);
    }
}

void Http2ServerConnection::close_logical_stream(std::uint32_t stream_id, bool notify_client) {
    connecting_streams_.erase(stream_id);
    const auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        if (notify_client) {
            enqueue_downlink(FrameType::Close, stream_id, {});
        }
        signal_notifier(loop_notifier_, "server", "loop");
        return;
    }
    PROXY_LOG(Debug, "[server] 关闭上游流 stream=" << stream_id
                                                   << (notify_client ? " notify_client=yes" : " notify_client=no"));
    close_socket(it->second.sock);
    streams_.erase(it);
    purge_downlink_data_for_stream(stream_id);
    if (notify_client) {
        enqueue_downlink(FrameType::Close, stream_id, {});
    }
    signal_notifier(loop_notifier_, "server", "loop");
}

void Http2ServerConnection::close_all_upstreams() {
    connecting_streams_.clear();
    for (auto& kv : streams_) {
        close_socket(kv.second.sock);
    }
    streams_.clear();
    downlink_data_by_stream_.clear();
    downlink_data_round_robin_.clear();
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
        if (nghttp2_session_set_local_window_size(h2_, NGHTTP2_FLAG_NONE, stream_id, kHttp2WindowSize) != 0) {
            submit_static_response(stream_id, 500, "text/plain", to_bytes("failed to set event stream window"));
            return;
        }

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
        if (request.response_started) {
            return;
        }
        if (!tunnel_opened_) {
            submit_static_response(stream_id, 409, "text/plain", to_bytes("open stream required first"));
            return;
        }
        submit_static_response(stream_id, 200, "text/plain", to_bytes("ok"));
        if (nghttp2_session_set_local_window_size(h2_, NGHTTP2_FLAG_NONE, stream_id, kHttp2WindowSize) != 0) {
            PROXY_LOG(Warn, "[server] 设置 upload stream 窗口失败 stream=" << stream_id);
        }
        handle_upload_frames(request);
        return;
    }

    if (request.method == "POST" && request.path == "/api/tunnel/close") {
        submit_static_response(stream_id, 200, "text/plain", to_bytes("closed"));
        running_ = false;
        signal_notifier(loop_notifier_, "server", "loop");
        return;
    }

    submit_static_response(stream_id, 404, "text/plain", to_bytes("not found"));
}

void Http2ServerConnection::handle_upload_frames(RequestState& request) {
    std::vector<std::pair<FrameHeader, std::vector<std::uint8_t>>> frames;
    if (!consume_frames(request.body, frames)) {
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
                PROXY_LOG(Warn, "[server] Open 请求解析失败 stream=" << tunnel_stream_id);
                enqueue_downlink(FrameType::OpenFail, tunnel_stream_id, encode_open_fail("bad open request"));
                continue;
            }

            PROXY_LOG(Info, "[server] Open 请求 stream=" << tunnel_stream_id
                                                         << " requested=" << requested_host << ":" << requested_port
                                                         << " atyp=" << socks5_atyp_name(atyp)
                                                         << " route="
                                                         << describe_upstream_route(config_, requested_host,
                                                                                    requested_port));

            if (streams_.find(tunnel_stream_id) != streams_.end() ||
                connecting_streams_.find(tunnel_stream_id) != connecting_streams_.end()) {
                PROXY_LOG(Warn, "[server] Open 重复 stream=" << tunnel_stream_id);
                enqueue_downlink(FrameType::OpenFail, tunnel_stream_id, encode_open_fail("stream already exists"));
                continue;
            }
            start_upstream_connect(tunnel_stream_id, atyp, requested_host, requested_port);
            PROXY_LOG(Debug, "[server] Open 异步连接已启动 stream=" << tunnel_stream_id
                                                                   << " requested=" << requested_host << ":"
                                                                   << requested_port);
            signal_notifier(loop_notifier_, "server", "loop");
        } else if (type == FrameType::Data) {
            const auto stream_it = streams_.find(tunnel_stream_id);
            if (stream_it == streams_.end()) {
                if (connecting_streams_.find(tunnel_stream_id) != connecting_streams_.end()) {
                    PROXY_LOG(Debug, "[server] 上游尚未建立，暂不接收 stream=" << tunnel_stream_id
                                                                            << " bytes=" << item.second.size());
                } else {
                    PROXY_LOG(Debug, "[server] 丢弃未知流数据 stream=" << tunnel_stream_id
                                                                      << " bytes=" << item.second.size());
                }
                continue;
            }
            auto& stream = stream_it->second;
            stream.pending_uplink.insert(stream.pending_uplink.end(), item.second.begin(), item.second.end());
            std::string error;
            if (!flush_upstream_socket(stream, error)) {
                PROXY_LOG(Debug, "[server] 上游发送失败 stream=" << tunnel_stream_id << " error=" << error);
                close_logical_stream(tunnel_stream_id, true);
                continue;
            }
            signal_notifier(loop_notifier_, "server", "loop");
        } else if (type == FrameType::Close) {
            PROXY_LOG(Debug, "[server] 收到客户端 Close stream=" << tunnel_stream_id);
            close_logical_stream(tunnel_stream_id, false);
        } else if (type == FrameType::Ping) {
            enqueue_downlink(FrameType::Pong, 0, item.second);
        }
    }
}

nghttp2_ssize Http2ServerConnection::read_response_body(nghttp2_session* /*session*/, int32_t /*stream_id*/, uint8_t* buf,
                                                        size_t length, uint32_t* data_flags, nghttp2_data_source* source,
                                                        void* user_data) {
    auto* self = static_cast<Http2ServerConnection*>(user_data);
    auto* request = static_cast<RequestState*>(source->ptr);
    if (request->response_mode == RequestState::ResponseMode::EventStream) {
        DownlinkFrame* active_frame = nullptr;
        if (!self->downlink_control_.empty()) {
            active_frame = &self->downlink_control_.front();
        } else {
            active_frame = self->current_downlink_data_frame();
        }

        if (active_frame == nullptr) {
            if (!self->running_) {
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
                const std::uint32_t stream_id = self->downlink_data_round_robin_.front();
                auto stream_it = self->downlink_data_by_stream_.find(stream_id);
                if (stream_it != self->downlink_data_by_stream_.end() && !stream_it->second.empty()) {
                    stream_it->second.pop_front();
                    self->downlink_data_round_robin_.pop_front();
                    if (!stream_it->second.empty()) {
                        self->downlink_data_round_robin_.push_back(stream_id);
                    } else {
                        self->downlink_data_by_stream_.erase(stream_it);
                    }
                } else {
                    self->downlink_data_round_robin_.pop_front();
                    if (stream_it != self->downlink_data_by_stream_.end()) {
                        self->downlink_data_by_stream_.erase(stream_it);
                    }
                }
            }
            if (!self->running_ && self->downlink_control_.empty() && !self->has_pending_downlink_data()) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            } else if (!self->downlink_control_.empty() || self->has_pending_downlink_data()) {
                nghttp2_session_resume_data(self->h2_, self->event_stream_id_);
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
    if (it->second.method == "POST" && it->second.path == "/api/tunnel/upload") {
        self->handle_upload_frames(it->second);
    }
    return 0;
}

int Http2ServerConnection::on_frame_recv(nghttp2_session* /*session*/, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<Http2ServerConnection*>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        const auto it = self->requests_.find(frame->hd.stream_id);
        if (it != self->requests_.end() &&
            it->second.method == "POST" && it->second.path == "/api/tunnel/upload" &&
            !it->second.response_started) {
            self->handle_request(frame->hd.stream_id);
        }
    }
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
