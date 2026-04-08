#include "common/logging.h"
#include "common/socks5.h"
#include "common/tls_wrapper.h"
#include "common/tunnel_protocol.h"

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstring>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <random>
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
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif

namespace {

constexpr std::size_t kTunnelIoChunkSize   = 256 * 1024;
constexpr std::int32_t kHttp2WindowSize    = 16 * 1024 * 1024;
constexpr std::uint32_t kHttp2MaxFrameSize = 1024 * 1024;
constexpr std::size_t kMaxBufferedDownlinkBytes = 32 * 1024 * 1024;
constexpr std::size_t kMaxUplinkBuffer      = 16 * 1024 * 1024;  // Backpressure limit

using proxy::close_socket;
using proxy::EventDispatcher;
using proxy::EventNotifier;
using proxy::kInvalidSocket;
using proxy::parse_log_level;
using proxy::perform_socks5_handshake;
using proxy::send_socks5_reply;
using proxy::send_all_raw;
using proxy::set_log_level;
using proxy::select_http2_padded_length;
using proxy::SocketEvent;
using proxy::socket_t;
using proxy::LogLevel;
using proxy::Socks5HandshakeStatus;
using proxy::Socks5Request;
using proxy::TlsSocket;

struct ClientConfig {
    std::string server_host;
    std::string listen_host;
    std::uint16_t server_port = 8443;
    std::uint16_t listen_port = 1080;
    std::string auth_password;
    std::string ech_config;
    bool enable_ech_grease = true;
    LogLevel log_level = LogLevel::Info;
};

enum class LocalProxyProtocol {
    Socks5,
    HttpConnect,
    HttpForward
};

struct AcceptedProxyRequest {
    Socks5Request target;
    LocalProxyProtocol protocol = LocalProxyProtocol::Socks5;
    std::vector<std::uint8_t> initial_payload;
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

bool parse_host_port(const std::string& text, std::string& host, std::uint16_t& port) {
    if (text.empty()) return false;
    if (text.front() == '[') {
        const auto end = text.find(']');
        const auto colon = text.rfind(':');
        if (end == std::string::npos || colon == std::string::npos || colon <= end) return false;
        host = text.substr(1, end - 1);
        port = static_cast<std::uint16_t>(std::stoi(text.substr(colon + 1)));
        return true;
    }
    const auto colon = text.rfind(':');
    if (colon == std::string::npos) return false;
    host = text.substr(0, colon);
    port = static_cast<std::uint16_t>(std::stoi(text.substr(colon + 1)));
    return !host.empty();
}

std::string describe_socks5_target(const Socks5Request& req) {
    return req.host + ":" + std::to_string(req.port);
}

const char* socks5_atyp_name(std::uint8_t atyp) {
    switch (atyp) {
        case 0x01: return "ipv4";
        case 0x03: return "domain";
        case 0x04: return "ipv6";
        default:   return "unknown";
    }
}

std::string ascii_lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return text;
}

std::string trim_ascii(std::string text) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    auto begin = std::find_if(text.begin(), text.end(), not_space);
    if (begin == text.end()) return {};
    auto end = std::find_if(text.rbegin(), text.rend(), not_space).base();
    return std::string(begin, end);
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

std::uint8_t detect_atyp_from_host(const std::string& host) {
    in_addr ipv4{};
    if (::inet_pton(AF_INET, host.c_str(), &ipv4) == 1) return 0x01;
    in6_addr ipv6{};
    if (::inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) return 0x04;
    return 0x03;
}

bool recv_http_headers(socket_t sock, std::string& raw_request, std::size_t& header_end,
                       std::string& error) {
    raw_request.clear();
    header_end = std::string::npos;
    constexpr std::size_t kMaxHeaderBytes = 64 * 1024;
    std::array<char, 4096> buf{};

    while (raw_request.size() < kMaxHeaderBytes) {
#ifdef _WIN32
        const int ret = ::recv(sock, buf.data(), static_cast<int>(buf.size()), 0);
#else
        const int ret = static_cast<int>(::recv(sock, buf.data(), buf.size(), 0));
#endif

        if (ret == 0) {
            error = "HTTP 客户端已断开";
            return false;
        }
        if (ret < 0) {
            // SO_RCVTIMEO 超时时返回 EAGAIN/EWOULDBLOCK
#ifdef _WIN32
            const int recv_errno = WSAGetLastError();
            if (recv_errno == WSAETIMEDOUT || recv_errno == WSAEWOULDBLOCK) {
#else
            const int recv_errno = errno;
            if (recv_errno == EAGAIN || recv_errno == EWOULDBLOCK) {
#endif
                error = "读取 HTTP 请求头超时";
            } else {
                error = "读取 HTTP 请求头失败";
            }
            return false;
        }

        raw_request.append(buf.data(), static_cast<std::size_t>(ret));
        header_end = raw_request.find("\r\n\r\n");
        if (header_end != std::string::npos) return true;
    }
    error = "HTTP 请求头过大";
    return false;
}

bool parse_http_proxy_request(socket_t sock, AcceptedProxyRequest& accepted,
                               std::string& error) {
    std::string raw_request;
    std::size_t header_end = std::string::npos;
    if (!recv_http_headers(sock, raw_request, header_end, error)) return false;
    if (header_end == std::string::npos) { error = "HTTP 请求头不完整"; return false; }

    std::istringstream stream(raw_request.substr(0, header_end));
    std::string request_line;
    if (!std::getline(stream, request_line)) { error = "HTTP 请求行为空"; return false; }
    if (!request_line.empty() && request_line.back() == '\r') request_line.pop_back();

    std::istringstream rls(request_line);
    std::string method, target_text, version;
    rls >> method >> target_text >> version;
    if (method.empty() || target_text.empty() || version.empty()) {
        error = "HTTP 请求行格式错误"; return false;
    }

    std::vector<std::pair<std::string, std::string>> headers;
    std::string host_header;
    for (std::string line; std::getline(stream, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) { error = "HTTP 请求头格式错误"; return false; }
        std::string name  = trim_ascii(line.substr(0, colon));
        std::string value = trim_ascii(line.substr(colon + 1));
        if (ascii_lower(name) == "host") host_header = value;
        headers.emplace_back(std::move(name), std::move(value));
    }

    Socks5Request req;
    if (ascii_lower(method) == "connect") {
        if (!parse_host_port(target_text, req.host, req.port)) {
            const auto c = target_text.rfind(':');
            if (c == std::string::npos) { error = "CONNECT 缺少目标端口"; return false; }
            req.host = target_text.substr(0, c);
            req.port = static_cast<std::uint16_t>(std::stoi(target_text.substr(c + 1)));
        }
        req.atyp = detect_atyp_from_host(req.host);
        accepted.target = std::move(req);
        accepted.protocol = LocalProxyProtocol::HttpConnect;
        accepted.initial_payload.clear();
        return true;
    }

    std::string remote_host;
    std::uint16_t remote_port = 80;
    std::string request_target = target_text;
    const std::string lowered_target = ascii_lower(target_text);
    if (lowered_target.rfind("http://", 0) == 0) {
        const std::string authority_and_path = target_text.substr(7);
        const auto slash = authority_and_path.find('/');
        const std::string authority = slash == std::string::npos
            ? authority_and_path : authority_and_path.substr(0, slash);
        request_target = slash == std::string::npos ? "/" : authority_and_path.substr(slash);
        if (!parse_host_port(authority, remote_host, remote_port)) {
            remote_host = authority; remote_port = 80;
        }
    } else {
        if (host_header.empty()) { error = "HTTP 代理请求缺少 Host"; return false; }
        if (!parse_host_port(host_header, remote_host, remote_port)) {
            remote_host = host_header; remote_port = 80;
        }
    }
    if (remote_host.empty()) { error = "无法解析 HTTP 目标主机"; return false; }

    req.host  = remote_host;
    req.port  = remote_port;
    req.atyp  = detect_atyp_from_host(req.host);

    std::ostringstream rebuilt;
    rebuilt << method << " " << request_target << " " << version << "\r\n";
    bool has_host = false;
    for (const auto& header : headers) {
        const std::string lower_name = ascii_lower(header.first);
        if (lower_name == "proxy-connection") continue;
        if (lower_name == "host") has_host = true;
        rebuilt << header.first << ": " << header.second << "\r\n";
    }
    if (!has_host) {
        rebuilt << "Host: " << remote_host;
        if (remote_port != 80) rebuilt << ":" << remote_port;
        rebuilt << "\r\n";
    }
    rebuilt << "\r\n";

    accepted.target = std::move(req);
    accepted.protocol = LocalProxyProtocol::HttpForward;
    const std::string rebuilt_request = rebuilt.str();
    accepted.initial_payload.assign(rebuilt_request.begin(), rebuilt_request.end());
    const std::size_t body_offset = header_end + 4;
    if (body_offset < raw_request.size()) {
        accepted.initial_payload.insert(accepted.initial_payload.end(),
                                        raw_request.begin() + static_cast<std::ptrdiff_t>(body_offset),
                                        raw_request.end());
    }
    return true;
}

bool send_http_proxy_response(socket_t sock, int status_code, const std::string& reason,
                               const std::string& body = {}) {
    std::ostringstream response;
    response << "HTTP/1.1 " << status_code << " " << reason << "\r\n";
    if (status_code == 200 && ascii_lower(reason) == "connection established") {
        response << "Proxy-Agent: qtunnel\r\n\r\n";
    } else {
        response << "Connection: close\r\n"
                 << "Content-Length: " << body.size() << "\r\n"
                 << "Content-Type: text/plain; charset=utf-8\r\n\r\n"
                 << body;
    }
    const std::string payload = response.str();
    std::string error;
    return send_all_raw(sock, reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), error);
}

bool accept_local_proxy_request(socket_t sock, AcceptedProxyRequest& accepted,
                                 std::string& error) {
    unsigned char first_byte = 0;
#ifdef _WIN32
    const int peeked = ::recv(sock, reinterpret_cast<char*>(&first_byte), 1, MSG_PEEK);
#else
    const int peeked = static_cast<int>(::recv(sock, &first_byte, 1, MSG_PEEK));
#endif
    if (peeked == 0) { error = "客户端已断开"; return false; }
    if (peeked < 0)  { error = "读取本地代理协议失败"; return false; }

    if (first_byte == 0x05) {
        accepted.protocol = LocalProxyProtocol::Socks5;
        accepted.initial_payload.clear();
        const Socks5HandshakeStatus hs = perform_socks5_handshake(sock, accepted.target, error);
        return hs == Socks5HandshakeStatus::Ok;
    }
    if (std::isalpha(first_byte) != 0) {
        accepted.protocol = LocalProxyProtocol::HttpForward;
        return parse_http_proxy_request(sock, accepted, error);
    }
    error = "不支持的本地代理协议";
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// LocalStream: one per proxied TCP connection
// ─────────────────────────────────────────────────────────────────────────────
// Helper struct for HTTP request parsing
struct HttpRequestBoundary {
    bool complete = false;
    std::size_t header_len = 0;   // bytes of headers incl \r\n\r\n
    std::size_t body_len = 0;     // Content-Length (0 = no body)
    bool chunked = false;         // Transfer-Encoding: chunked
    bool keep_alive = true;       // false if "Connection: close"
    std::string method;
    std::string target;
    std::string remote_host;
    uint16_t remote_port = 80;
};

// Forward declaration
struct LocalConnection;

struct LocalStream {
    int32_t h2_stream_id = -1;
    socket_t sock = kInvalidSocket;  // For SOCKS5 path; nullptr for HTTP
    std::shared_ptr<LocalConnection> conn;  // back-pointer to owning connection (HTTP only)

    enum class State { Pending, Open, Closed } state = State::Pending;

    LocalProxyProtocol protocol      = LocalProxyProtocol::Socks5;
    std::vector<std::uint8_t> initial_payload;  // forwarded after 200 (HTTP forward mode)

    // Per-stream mutex protects all fields below
    std::mutex mutex;

    // Downlink: server → local socket
    std::vector<std::uint8_t> pending_downlink;
    std::size_t pending_downlink_offset = 0;

    // Uplink: local socket → server
    std::vector<std::uint8_t> pending_uplink;
    bool uplink_eof      = false;  // local side closed
    bool uplink_deferred = false;  // H2 data provider is waiting for data

    // HTTP response status (populated during H2 response header parsing)
    int h2_status = 0;
};

// Owns a local TCP socket and manages a queue of H2 streams for HTTP pipelining
struct LocalConnection {
    socket_t sock = kInvalidSocket;
    bool is_connect_mode = false;  // true after CONNECT tunnel established (opaque TLS)

    std::mutex mutex;  // Guards all fields below

    // Ordered queue of active streams (for HTTP/1.1 pipelining)
    // Front = oldest (waiting to flush response to socket)
    std::deque<std::shared_ptr<LocalStream>> stream_queue;

    // Receive buffer: bytes from socket not yet dispatched to a stream
    std::vector<uint8_t> recv_buf;
    bool recv_eof = false;

    // For Forward mode: the stream currently receiving uplink body bytes
    std::shared_ptr<LocalStream> active_recv_stream;

    // Remaining bytes of current request body to route to active_recv_stream
    // 0 = at request boundary, ready to parse next request
    std::size_t body_remaining = 0;

    // true = chunked encoding or other pipeline-incompatible mode; route all further
    // bytes to active_recv_stream as opaque data
    bool pipeline_broken = false;
};

// Pending tunnel: accepted by pump thread, submitted as H2 CONNECT by io thread
struct PendingTunnel {
    socket_t sock = kInvalidSocket;  // For SOCKS5 path
    std::shared_ptr<LocalConnection> conn;  // For HTTP path (nullable)
    Socks5Request target;
    LocalProxyProtocol protocol;
    std::vector<std::uint8_t> initial_payload;
};

struct PendingHandshake {
    socket_t sock;
    std::string raw_request;  // Accumulated HTTP request data
};

// ─────────────────────────────────────────────────────────────────────────────
// ClientRuntime
// ─────────────────────────────────────────────────────────────────────────────
class ClientRuntime {
public:
    ClientRuntime(ClientConfig cfg, socket_t listener)
        : cfg_(std::move(cfg)), listener_(listener) {}
    ~ClientRuntime();

    bool start();
    bool should_retry() const { return should_retry_; }
    const std::string& last_error() const { return io_error_; }
    bool was_connected() const { return io_ok_; }
    static socket_t make_listener(std::uint16_t port, std::string host);

private:
    bool wait_for_io_ready();
    void io_loop();
    void process_pending_tunnels();
    void process_pending_resumes();
    bool flush_session();
    void send_decoy_request(const std::string& path);

    // Called from io_thread when server responds 200 to our CONNECT
    void handle_stream_open(int32_t h2_stream_id, const std::shared_ptr<LocalStream>& stream);
    // Called from io_thread when server responds non-200 or stream fails
    void handle_stream_fail(const std::shared_ptr<LocalStream>& stream, int status);

    void accept_and_pump_loop();
    void accept_one();
    void retry_pending_handshakes();  // Retry incomplete handshakes in pump loop (SOCKS5 only)
    void pump_local_socket(const std::shared_ptr<LocalStream>& stream);  // DEPRECATED, use pump_local_connection
    bool flush_local_socket(const std::shared_ptr<LocalStream>& stream, std::string& error);
    // Close local socket and signal uplink EOF so H2 sends END_STREAM
    void close_local_stream(const std::shared_ptr<LocalStream>& stream);

    // NEW: Per-request H2 tunnel functions
    void pump_local_connection(const std::shared_ptr<LocalConnection>& conn);
    bool flush_local_connection(const std::shared_ptr<LocalConnection>& conn, std::string& error);
    void close_local_connection(const std::shared_ptr<LocalConnection>& conn);
    void drain_pending_conn_close();
    std::shared_ptr<LocalStream> try_parse_next_request(const std::shared_ptr<LocalConnection>& conn);

    void close_all_streams();

    // nghttp2 callbacks
    static nghttp2_ssize uplink_read_callback(nghttp2_session* session, int32_t stream_id,
                                               uint8_t* buf, size_t length,
                                               uint32_t* data_flags, nghttp2_data_source* source,
                                               void* user_data);
    static int on_begin_headers(nghttp2_session*, const nghttp2_frame*, void*);
    static int on_header(nghttp2_session*, const nghttp2_frame*, const uint8_t* name,
                         size_t namelen, const uint8_t* value, size_t valuelen,
                         uint8_t flags, void* user_data);
    static int on_data_chunk_recv(nghttp2_session*, uint8_t flags, int32_t stream_id,
                                   const uint8_t* data, size_t len, void* user_data);
    static int on_frame_recv(nghttp2_session*, const nghttp2_frame*, void* user_data);
    static int on_stream_close(nghttp2_session*, int32_t stream_id, uint32_t error_code,
                                void* user_data);
    static nghttp2_ssize select_padding(nghttp2_session*, const nghttp2_frame*,
                                        size_t max_payloadlen, void*);

    ClientConfig cfg_;
    socket_t     listener_ = kInvalidSocket;
    TlsSocket    tls_;
    nghttp2_session* h2_ = nullptr;
    std::thread  io_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> io_ready_{false};
    std::atomic<bool> io_ok_{false};
    std::string  io_error_;
    std::string  peer_fingerprint_;
    bool         should_retry_ = false;

    // streams_ is OWNED by io_thread (only io_thread adds/removes entries).
    // Pump thread takes read-only snapshots under streams_mutex_.
    std::mutex streams_mutex_;
    std::map<int32_t, std::shared_ptr<LocalStream>> streams_;

    // New tunnel requests created by pump thread, consumed by io_thread
    std::mutex pending_mutex_;
    std::deque<PendingTunnel> pending_tunnels_;

    // Incomplete HTTP handshakes waiting for more data (pump thread only)
    std::deque<PendingHandshake> pending_handshakes_;

    // H2 stream IDs whose data providers need to be resumed (written by pump, read by io)
    std::mutex resume_mutex_;
    std::set<int32_t> pending_resume_;

    // Local TCP connections (pump_thread owned)
    // Maps socket → LocalConnection
    std::map<socket_t, std::shared_ptr<LocalConnection>> connections_;

    // Connections to close (written by io_thread, consumed by pump_thread)
    std::mutex conn_close_mutex_;
    std::deque<std::shared_ptr<LocalConnection>> pending_conn_close_;

    // Decoy/virtual GET requests (io_thread only, no mutex needed)
    std::set<int32_t> decoy_stream_ids_;
    std::chrono::steady_clock::time_point next_decoy_time_;
    bool decoy_initial_sent_ = false;
    std::mt19937 decoy_rng_{std::random_device{}()};

    EventNotifier io_notifier_;
    EventNotifier local_loop_notifier_;
};

// ─────────────────────────────────────────────────────────────────────────────

ClientRuntime::~ClientRuntime() {
    running_ = false;
    signal_notifier(io_notifier_, "client", "destructor");
    signal_notifier(local_loop_notifier_, "client", "destructor");
    tls_.shutdown();
    if (io_thread_.joinable()) io_thread_.join();
    io_notifier_.close();
    local_loop_notifier_.close();
    close_all_streams();
    if (h2_) { nghttp2_session_del(h2_); h2_ = nullptr; }
}

bool ClientRuntime::wait_for_io_ready() {
    for (int i = 0; i < 200; ++i) {
        if (io_ready_) return io_ok_.load();
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    io_error_ = "等待 HTTP/2 连接初始化超时";
    return false;
}

bool ClientRuntime::start() {
    should_retry_ = false;
    running_ = true;
    if (listener_ == kInvalidSocket) {
        io_error_ = "本地监听未初始化";
        should_retry_ = true;  // Allow retry even on initialization error
        return false;
    }

    std::string notifier_error;
    if (!io_notifier_.open(notifier_error) || !local_loop_notifier_.open(notifier_error)) {
        io_error_ = notifier_error.empty() ? "初始化事件唤醒器失败" : notifier_error;
        running_ = false;
        should_retry_ = true;  // Allow retry
        return false;
    }

    PROXY_LOG(Info, "[client] 正在连接 " << cfg_.server_host << ":" << cfg_.server_port << " ...");
    io_thread_ = std::thread(&ClientRuntime::io_loop, this);

    if (!wait_for_io_ready()) {
        PROXY_LOG(Error, "[client] HTTP/2 初始化失败: " << io_error_);
        running_ = false;
        should_retry_ = true;  // Allow retry on connection failure
        signal_notifier(local_loop_notifier_, "client", "local-loop");
        tls_.shutdown();
        if (io_thread_.joinable()) io_thread_.join();
        io_notifier_.close();
        local_loop_notifier_.close();
        return false;
    }

    PROXY_LOG(Info, "[client] HTTP/2 TLS 连接已建立到 "
              << cfg_.server_host << ":" << cfg_.server_port);
    if (!peer_fingerprint_.empty()) {
        PROXY_LOG(Debug, "[client] 服务器证书 SHA-256 指纹: " << peer_fingerprint_);
    }
    PROXY_LOG(Info, "[client] 本地代理监听 "
              << cfg_.listen_host << ":" << cfg_.listen_port << " (SOCKS5 + HTTP)");

    should_retry_ = true;
    accept_and_pump_loop();

    if (!io_error_.empty()) {
        PROXY_LOG(Error, "[client] 客户端停止: " << io_error_);
        return false;
    }
    return running_;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Request Boundary Detection (for pipelined HTTP requests)
// ─────────────────────────────────────────────────────────────────────────────

bool parse_http_boundary(const std::vector<uint8_t>& buf, HttpRequestBoundary& out) {
    // Find end of headers
    const char* data = reinterpret_cast<const char*>(buf.data());
    std::size_t size = buf.size();

    const char* eol = std::search(data, data + size, "\r\n\r\n", "\r\n\r\n" + 4);
    if (eol == data + size) {
        out.complete = false;
        return false;  // Headers not complete
    }

    std::size_t header_len = (eol - data) + 4;
    out.header_len = header_len;

    // Parse request line
    std::istringstream stream(std::string(data, eol - data - 2));
    std::string method, target, version;
    if (!(stream >> method >> target >> version)) {
        return false;  // Invalid request line
    }

    out.method = method;
    out.target = target;

    // For CONNECT, parse the target as host:port
    if (ascii_lower(method) == "connect") {
        const auto colon = target.rfind(':');
        if (colon != std::string::npos) {
            out.remote_host = target.substr(0, colon);
            try {
                out.remote_port = static_cast<uint16_t>(std::stoi(target.substr(colon + 1)));
            } catch (...) {
                out.remote_port = 443;  // default HTTPS port
            }
        } else {
            out.remote_host = target;
            out.remote_port = 443;
        }
    }

    // Parse headers for Content-Length, Transfer-Encoding, Connection
    std::string line;
    std::size_t body_len = 0;
    bool has_content_length = false;
    bool chunked_encoding = false;

    while (std::getline(stream, line)) {
        if (line.empty() || line == "\r") break;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string hname = line.substr(0, colon);
        std::string hvalue = line.substr(colon + 1);

        // Trim whitespace
        while (!hname.empty() && std::isspace(hname.back())) hname.pop_back();
        while (!hvalue.empty() && std::isspace(hvalue[0])) hvalue = hvalue.substr(1);

        if (ascii_lower(hname) == "content-length") {
            try {
                body_len = std::stoul(hvalue);
                has_content_length = true;
            } catch (...) {}
        } else if (ascii_lower(hname) == "transfer-encoding") {
            if (hvalue.find("chunked") != std::string::npos) {
                chunked_encoding = true;
            }
        } else if (ascii_lower(hname) == "connection") {
            if (ascii_lower(hvalue).find("close") != std::string::npos) {
                out.keep_alive = false;
            }
        }
    }

    // Methods that must not have a body
    std::string method_lower = ascii_lower(method);
    if (method_lower == "get" || method_lower == "head" || method_lower == "delete" ||
        method_lower == "options" || method_lower == "trace") {
        body_len = 0;
        has_content_length = true;
    }

    out.chunked = chunked_encoding;
    out.body_len = body_len;
    out.complete = !chunked_encoding && (has_content_length || body_len == 0);

    return out.complete;
}

// ─────────────────────────────────────────────────────────────────────────────
// IO thread
// ─────────────────────────────────────────────────────────────────────────────

void ClientRuntime::io_loop() {
    try {

    const auto finish_with_error = [&](const std::string& error) {
        PROXY_LOG(Error, "[client] IO 线程退出: " << error);
        io_error_  = error;
        io_ok_     = false;
        io_ready_  = true;
        running_   = false;
        signal_notifier(local_loop_notifier_, "client", "io-error");
    };

    tls_.set_enable_ech_grease(cfg_.enable_ech_grease);
    tls_.set_ech_config_base64(cfg_.ech_config);
    if (!tls_.connect_client(cfg_.server_host, cfg_.server_port, cfg_.server_host)) {
        finish_with_error(tls_.last_error()); return;
    }
    peer_fingerprint_ = tls_.peer_fingerprint();

    PROXY_LOG(Debug, "[client] TLS version: " << tls_.negotiated_tls_version());
    PROXY_LOG(Debug, "[client] TLS cipher: "  << tls_.negotiated_cipher());
    PROXY_LOG(Debug, "[client] TLS ALPN: "
              << (tls_.negotiated_alpn().empty() ? "<none>" : tls_.negotiated_alpn()));
    PROXY_LOG(Debug, "[client] TLS ECH accepted: " << (tls_.ech_accepted() ? "yes" : "no"));
    if (!tls_.ech_name_override().empty()) {
        PROXY_LOG(Debug, "[client] TLS ECH name override: " << tls_.ech_name_override());
    }

    // ── Build nghttp2 client session ────────────────────────────────────────
    nghttp2_session_callbacks* cbs = nullptr;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, &ClientRuntime::on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cbs, &ClientRuntime::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, &ClientRuntime::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, &ClientRuntime::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, &ClientRuntime::on_stream_close);
    nghttp2_session_callbacks_set_select_padding_callback2(cbs, &ClientRuntime::select_padding);

    if (nghttp2_session_client_new(&h2_, cbs, this) != 0) {
        nghttp2_session_callbacks_del(cbs);
        finish_with_error("nghttp2_session_client_new 失败"); return;
    }
    nghttp2_session_callbacks_del(cbs);

    PROXY_LOG(Info, "[client] submitting SETTINGS...");
    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, static_cast<uint32_t>(kHttp2WindowSize)},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE,       kHttp2MaxFrameSize},
    };
    int settings_ret = nghttp2_submit_settings(h2_, NGHTTP2_FLAG_NONE, settings, 2);
    PROXY_LOG(Info, "[client] nghttp2_submit_settings returned " << settings_ret);
    if (settings_ret != 0) {
        finish_with_error("nghttp2_submit_settings 失败"); return;
    }
    
    int window_ret = nghttp2_session_set_local_window_size(h2_, NGHTTP2_FLAG_NONE, 0, kHttp2WindowSize);
    PROXY_LOG(Info, "[client] nghttp2_session_set_local_window_size returned " << window_ret);
    if (window_ret != 0) {
        finish_with_error("nghttp2_session_set_local_window_size 失败"); return;
    }
    
    PROXY_LOG(Info, "[client] flushing initial session data...");
    if (!flush_session()) {
        finish_with_error("发送 HTTP/2 SETTINGS 失败"); return;
    }
    PROXY_LOG(Info, "[client] initial flush complete");

    io_ok_    = true;
    io_ready_ = true;

    // Initialize decoy request timing
    next_decoy_time_ = std::chrono::steady_clock::now();
    decoy_initial_sent_ = false;

    // ── Event loop ──────────────────────────────────────────────────────────
    EventDispatcher dispatcher;
    if (!dispatcher.valid()) { finish_with_error("初始化 HTTP/2 事件分发器失败"); return; }

    std::string de;
    if (!dispatcher.set(tls_.raw_socket(), true, false, de) ||
        !dispatcher.set(io_notifier_.readable_socket(), true, false, de)) {
        finish_with_error(de); return;
    }

    while (running_) {
        // Submit any new CONNECT streams requested by the pump thread
        process_pending_tunnels();

        // Resume data providers that have new uplink data
        process_pending_resumes();

        // Check and send decoy GET requests
        auto now = std::chrono::steady_clock::now();
        if (now >= next_decoy_time_) {
            if (!decoy_initial_sent_) {
                send_decoy_request("/");
                decoy_initial_sent_ = true;
                // Send favicon 1-3s later
                next_decoy_time_ = now + std::chrono::milliseconds(1000 + decoy_rng_() % 2000);
            } else {
                send_decoy_request("/favicon.ico");
                // Next decoy request in 30-90s
                next_decoy_time_ = now + std::chrono::seconds(30 + decoy_rng_() % 60);
            }
        }

        if (!flush_session()) {
            io_error_ = "发送 HTTP/2 帧失败";
            running_  = false;
            break;
        }

        std::vector<SocketEvent> events;
        // Calculate wait timeout based on next decoy request time
        // But use a short timeout (100ms) to ensure we process pending tunnels frequently
        auto ms_until_decoy = std::chrono::duration_cast<std::chrono::milliseconds>(
            next_decoy_time_ - std::chrono::steady_clock::now()).count();
        int wait_ms = 100;  // Short timeout to process pending tunnels quickly
        if (ms_until_decoy > 0 && ms_until_decoy < 100) {
            wait_ms = static_cast<int>(ms_until_decoy);
        }
        const int ready = dispatcher.wait(events, wait_ms, de);
        if (ready < 0) {
            io_error_ = de;
            running_  = false;
            break;
        }

        bool got_tls_data = false;
        for (const auto& ev : events) {
            if (ev.sock == io_notifier_.readable_socket()) {
                io_notifier_.drain();
                continue;
            }
            if (ev.sock == tls_.raw_socket() && (ev.readable || ev.error || ev.hangup)) {
                got_tls_data = true;
            }
        }

        if (got_tls_data) {
            std::array<std::uint8_t, kTunnelIoChunkSize> buf{};
            const int ret = tls_.read(buf.data(), buf.size());
            if (ret <= 0) {
                io_error_ = tls_.last_error().empty() ? "HTTP/2 连接已断开" : tls_.last_error();
                running_  = false;
                break;
            }
            const auto consumed = nghttp2_session_mem_recv2(h2_, buf.data(),
                                                             static_cast<std::size_t>(ret));
            if (consumed < 0) {
                io_error_ = std::string("nghttp2_session_mem_recv2 失败: ")
                            + nghttp2_strerror(static_cast<int>(consumed));
                running_  = false;
                break;
            }
            if (!flush_session()) {
                io_error_ = "发送 HTTP/2 帧失败";
                running_  = false;
                break;
            }
        }
    }

    // Tear down all streams
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        for (auto& kv : streams_) {
            socket_t sock = kInvalidSocket;
            {
                std::lock_guard<std::mutex> sl(kv.second->mutex);
                sock = kv.second->sock;
                kv.second->sock  = kInvalidSocket;
                kv.second->state = LocalStream::State::Closed;
                kv.second->uplink_eof = true;
            }
            if (sock != kInvalidSocket) close_socket(sock);
        }
        streams_.clear();
    }

    if (!io_error_.empty()) {
        PROXY_LOG(Warn, "[client] HTTP/2 会话结束: " << io_error_);
    }
    signal_notifier(local_loop_notifier_, "client", "io-done");

    } catch (const std::exception& ex) {
        io_error_ = std::string("io_loop 未捕获异常: ") + ex.what();
        PROXY_LOG(Error, "[client] " << io_error_);
        io_ok_    = false;
        io_ready_ = true;
        running_  = false;
        signal_notifier(local_loop_notifier_, "client", "io-exception");
    } catch (...) {
        io_error_ = "io_loop 未捕获未知异常";
        PROXY_LOG(Error, "[client] " << io_error_);
        io_ok_    = false;
        io_ready_ = true;
        running_  = false;
        signal_notifier(local_loop_notifier_, "client", "io-exception");
    }
}

void ClientRuntime::process_pending_tunnels() {
    std::deque<PendingTunnel> tunnels;
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        tunnels.swap(pending_tunnels_);
    }

    for (auto& pt : tunnels) {
        auto stream = std::make_shared<LocalStream>();

        // Determine if this is SOCKS5 or HTTP path
        bool is_http_path = pt.conn != nullptr;

        if (!is_http_path) {
            // SOCKS5 path: stream owns the socket
            stream->sock = pt.sock;
        } else {
            // HTTP path: stream is owned by LocalConnection
            stream->conn = pt.conn;
            stream->sock = kInvalidSocket;
        }

        stream->protocol        = pt.protocol;
        stream->initial_payload = std::move(pt.initial_payload);

        // HTTP/2 CONNECT headers (no :scheme, no :path per RFC 7540 §8.3)
        const std::string authority = pt.target.host + ":" + std::to_string(pt.target.port);

        // 先收集所有headers到vector，确保容量足够后再创建nghttp2_nv
        // 因为vector重新分配会使之前保存的指针失效
        std::vector<std::string> header_storage;
        header_storage.reserve(6);  // 最多6个: method, CONNECT, authority, host:port, x-tunnel-auth, password
        header_storage.push_back(":method");
        header_storage.push_back("CONNECT");
        header_storage.push_back(":authority");
        header_storage.push_back(authority);

        std::vector<nghttp2_nv> hdrs;
        hdrs.push_back(make_nv(header_storage[0], header_storage[1]));
        hdrs.push_back(make_nv(header_storage[2], header_storage[3]));

        if (!cfg_.auth_password.empty()) {
            header_storage.push_back("x-tunnel-auth");
            header_storage.push_back(cfg_.auth_password);
            hdrs.push_back(make_nv(header_storage[4], header_storage[5]));
        }

        // Data provider for uplink (local socket → server)
        nghttp2_data_provider2 provider{};
        provider.read_callback = &ClientRuntime::uplink_read_callback;

        PROXY_LOG(Info, "[client] submitting H2 request with " << hdrs.size() << " headers");
        for (const auto& h : hdrs) {
            std::string name(reinterpret_cast<const char*>(h.name), h.namelen);
            std::string value(reinterpret_cast<const char*>(h.value), h.valuelen);
            PROXY_LOG(Debug, "[client]   " << name << ": " << value);
        }

        const int32_t sid = nghttp2_submit_request2(
            h2_, nullptr, hdrs.data(), hdrs.size(), &provider, this);
        if (sid < 0) {
            PROXY_LOG(Error, "[client] H2 CONNECT submit 失败: " << nghttp2_strerror(sid));
            if (!is_http_path) {
                close_socket(pt.sock);
            }
            continue;
        }

        stream->h2_stream_id = sid;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            streams_[sid] = stream;
        }

        // For HTTP path: now add the stream to the connection's queue
        // (after h2_stream_id has been assigned)
        if (is_http_path && pt.conn) {
            std::lock_guard<std::mutex> lock(pt.conn->mutex);
            pt.conn->stream_queue.push_back(stream);
            PROXY_LOG(Debug, "[client] added stream " << sid << " to connection queue");
        }

        PROXY_LOG(Info, "[client] H2 CONNECT stream=" << sid << " target=" << authority
                      << " SUBMITTED (will be flushed in next flush_session call)");
    }
}

void ClientRuntime::send_decoy_request(const std::string& path) {
    // 构造 Chrome 风格的 GET 请求
    std::vector<std::string> header_storage;
    header_storage.reserve(14);

    // Pseudo-headers
    header_storage.push_back(":method");
    header_storage.push_back("GET");
    header_storage.push_back(":scheme");
    header_storage.push_back("https");
    header_storage.push_back(":authority");
    header_storage.push_back(cfg_.server_host);
    header_storage.push_back(":path");
    header_storage.push_back(path);

    // Regular headers - Chrome style
    header_storage.push_back("user-agent");
    header_storage.push_back("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    header_storage.push_back("accept");
    if (path == "/favicon.ico") {
        header_storage.push_back("image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8");
    } else {
        header_storage.push_back("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                                "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    }
    header_storage.push_back("accept-language");
    header_storage.push_back("en-US,en;q=0.9");
    header_storage.push_back("accept-encoding");
    header_storage.push_back("gzip, deflate, br");

    if (path == "/favicon.ico") {
        header_storage.push_back("sec-fetch-dest");
        header_storage.push_back("image");
        header_storage.push_back("sec-fetch-mode");
        header_storage.push_back("no-cors");
        header_storage.push_back("sec-fetch-site");
        header_storage.push_back("same-origin");
    } else {
        header_storage.push_back("sec-fetch-dest");
        header_storage.push_back("document");
        header_storage.push_back("sec-fetch-mode");
        header_storage.push_back("navigate");
        header_storage.push_back("sec-fetch-site");
        header_storage.push_back("none");
    }

    // Build nghttp2_nv array
    std::vector<nghttp2_nv> hdrs;
    for (size_t i = 0; i < header_storage.size(); i += 2) {
        hdrs.push_back(make_nv(header_storage[i], header_storage[i + 1]));
    }

    // Submit GET request (nullptr data_provider = no body, nghttp2 auto-sets END_STREAM)
    const int32_t sid = nghttp2_submit_request2(
        h2_, nullptr, hdrs.data(), hdrs.size(), nullptr, this);
    if (sid >= 0) {
        decoy_stream_ids_.insert(sid);
        PROXY_LOG(Debug, "[client] 虚拟 GET " << path << " stream=" << sid);
    } else {
        PROXY_LOG(Warn, "[client] 虚拟 GET " << path << " 失败: " << nghttp2_strerror(sid));
    }
}

void ClientRuntime::process_pending_resumes() {
    std::set<int32_t> to_resume;
    {
        std::lock_guard<std::mutex> lock(resume_mutex_);
        to_resume.swap(pending_resume_);
    }
    for (int32_t sid : to_resume) {
        // streams_ is safe to access without lock here: io_thread owns the map
        auto it = streams_.find(sid);
        if (it == streams_.end()) continue;
        auto& stream = it->second;
        std::lock_guard<std::mutex> sl(stream->mutex);
        if (stream->uplink_deferred &&
            (!stream->pending_uplink.empty() || stream->uplink_eof)) {
            stream->uplink_deferred = false;
            nghttp2_session_resume_data(h2_, sid);
        }
    }
}

bool ClientRuntime::flush_session() {
    std::size_t total_sent = 0;
    while (true) {
        const uint8_t* data = nullptr;
        const auto len = nghttp2_session_mem_send2(h2_, &data);
        if (len < 0) {
            PROXY_LOG(Error, "[client] nghttp2_session_mem_send2 failed: " << len);
            return false;
        }
        if (len == 0) {
            if (total_sent > 0) {
                PROXY_LOG(Debug, "[client] flush_session: sent " << total_sent << " bytes total");
            }
            return true;
        }

        PROXY_LOG(Debug, "[client] flush_session: sending " << len << " bytes");
        total_sent += len;
        if (!tls_.write_all(data, static_cast<std::size_t>(len))) {
            PROXY_LOG(Error, "[client] TLS write_all failed: " << tls_.last_error());
            return false;
        }
    }
}

void ClientRuntime::handle_stream_open(int32_t h2_stream_id,
                                        const std::shared_ptr<LocalStream>& stream) {
    LocalProxyProtocol protocol;
    socket_t sock = kInvalidSocket;
    std::vector<std::uint8_t> initial;
    auto conn = stream->conn;

    {
        std::lock_guard<std::mutex> sl(stream->mutex);
        stream->state = LocalStream::State::Open;
        protocol = stream->protocol;
        sock     = stream->sock;
        initial  = std::move(stream->initial_payload);
        // Initial payload (HTTP forward) becomes first uplink data
        if (!initial.empty()) {
            stream->pending_uplink.insert(stream->pending_uplink.end(),
                                          initial.begin(), initial.end());
        }
    }

    // For HTTP path: get socket from connection
    if (conn && sock == kInvalidSocket) {
        std::lock_guard<std::mutex> cl(conn->mutex);
        sock = conn->sock;
    }

    if (sock == kInvalidSocket) {
        return;  // No valid socket
    }

    // Send protocol-level success reply (for SOCKS5 and HTTP CONNECT)
    if (protocol == LocalProxyProtocol::Socks5) {
        send_socks5_reply(sock, 0x00);
        PROXY_LOG(Debug, "[client] stream=" << h2_stream_id << " SOCKS5 成功响应已发送");
    } else if (protocol == LocalProxyProtocol::HttpConnect) {
        send_http_proxy_response(sock, 200, "Connection Established");
        PROXY_LOG(Debug, "[client] stream=" << h2_stream_id << " HTTP CONNECT 200 已发送");

        // For HTTP CONNECT: mark connection as in CONNECT mode (opaque TLS tunnel)
        if (conn) {
            std::lock_guard<std::mutex> cl(conn->mutex);
            conn->is_connect_mode = true;
            conn->active_recv_stream = stream;
        }
    }
    // HttpForward: transparent, no reply

    // Switch local socket to non-blocking for the pump loop
    std::string err;
    proxy::set_socket_nonblocking(sock, true, err);

    signal_notifier(local_loop_notifier_, "client", "stream-open");

    // Resume data provider if it deferred waiting for uplink data
    {
        std::lock_guard<std::mutex> sl(stream->mutex);
        if (stream->uplink_deferred &&
            (!stream->pending_uplink.empty() || stream->uplink_eof)) {
            stream->uplink_deferred = false;
            nghttp2_session_resume_data(h2_, h2_stream_id);
        }
    }
}

void ClientRuntime::handle_stream_fail(const std::shared_ptr<LocalStream>& stream, int status) {
    LocalProxyProtocol protocol;
    socket_t sock;
    {
        std::lock_guard<std::mutex> sl(stream->mutex);
        protocol      = stream->protocol;
        sock          = stream->sock;
        stream->sock  = kInvalidSocket;
        stream->state = LocalStream::State::Closed;
        stream->uplink_eof = true;
    }
    PROXY_LOG(Warn, "[client] stream=" << stream->h2_stream_id
              << " CONNECT 失败 HTTP " << status);
    if (sock == kInvalidSocket) return;
    if (protocol == LocalProxyProtocol::Socks5) {
        send_socks5_reply(sock, 0x05);
    } else if (protocol == LocalProxyProtocol::HttpConnect ||
               protocol == LocalProxyProtocol::HttpForward) {
        send_http_proxy_response(sock, 502, "Bad Gateway", "tunnel connect failed");
    }
    close_socket(sock);
}

// ─────────────────────────────────────────────────────────────────────────────
// nghttp2 callbacks (always called from io_thread)
// ─────────────────────────────────────────────────────────────────────────────

nghttp2_ssize ClientRuntime::uplink_read_callback(nghttp2_session* /*session*/,
                                                   int32_t stream_id,
                                                   uint8_t* buf, size_t length,
                                                   uint32_t* data_flags,
                                                   nghttp2_data_source* /*source*/,
                                                   void* user_data) {
    auto* self = static_cast<ClientRuntime*>(user_data);

    // io_thread owns streams_; no lock needed for map lookup
    auto it = self->streams_.find(stream_id);
    if (it == self->streams_.end()) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    auto& stream = it->second;

    std::lock_guard<std::mutex> sl(stream->mutex);

    // Wait until stream is Open (200 received) before sending data
    if (stream->state == LocalStream::State::Pending) {
        PROXY_LOG(Debug, "[client] uplink_read_callback stream=" << stream_id << " Pending -> deferred");
        stream->uplink_deferred = true;
        return NGHTTP2_ERR_DEFERRED;
    }

    if (stream->pending_uplink.empty()) {
        if (stream->uplink_eof) {
            PROXY_LOG(Debug, "[client] uplink_read_callback stream=" << stream_id << " EOF");
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        PROXY_LOG(Debug, "[client] uplink_read_callback stream=" << stream_id << " no data -> deferred");
        stream->uplink_deferred = true;
        return NGHTTP2_ERR_DEFERRED;
    }

    const std::size_t n = std::min(length, stream->pending_uplink.size());
    PROXY_LOG(Info, "[client] uplink_read_callback stream=" << stream_id << " sending " << n << " bytes"
                  << " remaining=" << (stream->pending_uplink.size() - n));
    std::memcpy(buf, stream->pending_uplink.data(), n);
    stream->pending_uplink.erase(stream->pending_uplink.begin(),
                                  stream->pending_uplink.begin() + static_cast<std::ptrdiff_t>(n));

    // If more data remains, schedule another call
    if (!stream->pending_uplink.empty()) {
        nghttp2_session_resume_data(self->h2_, stream_id);
    } else if (stream->uplink_eof) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }

    return static_cast<nghttp2_ssize>(n);
}

int ClientRuntime::on_begin_headers(nghttp2_session* /*session*/,
                                     const nghttp2_frame* /*frame*/, void* /*user_data*/) {
    return 0;
}

int ClientRuntime::on_header(nghttp2_session* /*session*/, const nghttp2_frame* frame,
                              const uint8_t* name, size_t namelen,
                              const uint8_t* value, size_t valuelen,
                              uint8_t /*flags*/, void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_RESPONSE) return 0;

    auto* self = static_cast<ClientRuntime*>(user_data);
    auto it = self->streams_.find(frame->hd.stream_id);
    if (it == self->streams_.end()) return 0;

    const std::string hname(reinterpret_cast<const char*>(name), namelen);
    if (hname == ":status") {
        try {
            std::lock_guard<std::mutex> sl(it->second->mutex);
            it->second->h2_status = std::stoi(
                std::string(reinterpret_cast<const char*>(value), valuelen));
        } catch (...) {}
    }
    return 0;
}

int ClientRuntime::on_data_chunk_recv(nghttp2_session* /*session*/, uint8_t /*flags*/,
                                       int32_t stream_id, const uint8_t* data, size_t len,
                                       void* user_data) {
    auto* self = static_cast<ClientRuntime*>(user_data);
    auto it = self->streams_.find(stream_id);
    if (it == self->streams_.end()) return 0;
    auto& stream = it->second;

    bool buffered_too_much = false;
    bool should_signal = false;
    {
        std::lock_guard<std::mutex> sl(stream->mutex);

        // For SOCKS5 path: stream owns the socket
        // For HTTP path: socket is owned by LocalConnection, so stream->sock is intentionally invalid
        bool has_valid_socket = (stream->sock != kInvalidSocket) || (stream->conn != nullptr);

        if (stream->state != LocalStream::State::Open || !has_valid_socket) {
            return 0;
        }

        stream->pending_downlink.insert(stream->pending_downlink.end(), data, data + len);
        const std::size_t buffered = stream->pending_downlink.size()
                                   - stream->pending_downlink_offset;
        buffered_too_much = (buffered > kMaxBufferedDownlinkBytes);
        should_signal = !buffered_too_much;
    }
    PROXY_LOG(Debug, "[client] stream=" << stream_id << " 收到下行数据 bytes=" << len);

    if (buffered_too_much) {
        PROXY_LOG(Warn, "[client] stream=" << stream_id << " 下行缓冲过大，关闭流");
        self->close_local_stream(stream);
    } else if (should_signal) {
        signal_notifier(self->local_loop_notifier_, "client", "downlink");
    }
    return 0;
}

int ClientRuntime::on_frame_recv(nghttp2_session* /*session*/, const nghttp2_frame* frame,
                                  void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    if (frame->headers.cat != NGHTTP2_HCAT_RESPONSE) return 0;

    auto* self = static_cast<ClientRuntime*>(user_data);
    auto it = self->streams_.find(frame->hd.stream_id);
    if (it == self->streams_.end()) return 0;
    auto& stream = it->second;

    const int status = [&]() {
        std::lock_guard<std::mutex> sl(stream->mutex);
        return stream->h2_status;
    }();

    if (status == 200) {
        self->handle_stream_open(frame->hd.stream_id, stream);
    } else {
        self->handle_stream_fail(stream, status);
    }
    return 0;
}

int ClientRuntime::on_stream_close(nghttp2_session* /*session*/, int32_t stream_id,
                                    uint32_t /*error_code*/, void* user_data) {
    auto* self = static_cast<ClientRuntime*>(user_data);

    // Clean up decoy stream if applicable
    self->decoy_stream_ids_.erase(stream_id);

    std::shared_ptr<LocalStream> stream;
    {
        std::lock_guard<std::mutex> lock(self->streams_mutex_);
        auto it = self->streams_.find(stream_id);
        if (it == self->streams_.end()) return 0;
        stream = it->second;
        self->streams_.erase(it);
    }

    socket_t sock = kInvalidSocket;
    auto conn = stream->conn;

    {
        std::lock_guard<std::mutex> sl(stream->mutex);
        sock         = stream->sock;
        stream->sock = kInvalidSocket;
        stream->state = LocalStream::State::Closed;
        stream->uplink_eof = true;
    }

    // Handle HTTP path: dequeue from connection
    if (conn) {
        bool should_close_conn = false;
        {
            std::lock_guard<std::mutex> cl(conn->mutex);

            // Remove stream from queue if it's at the front
            if (!conn->stream_queue.empty() && conn->stream_queue.front() == stream) {
                conn->stream_queue.pop_front();

                // Check if connection should close
                if (conn->stream_queue.empty() && conn->recv_eof) {
                    should_close_conn = true;
                }
            }
        }

        if (should_close_conn) {
            // Queue connection for closure by pump thread
            {
                std::lock_guard<std::mutex> cl(self->conn_close_mutex_);
                self->pending_conn_close_.push_back(conn);
            }
            signal_notifier(self->local_loop_notifier_, "client", "conn-close");
        } else {
            // Signal pump thread to flush next queued stream
            signal_notifier(self->local_loop_notifier_, "client", "stream-closed");
        }
    } else {
        // SOCKS5 path: close socket immediately
        if (sock != kInvalidSocket) close_socket(sock);
        signal_notifier(self->local_loop_notifier_, "client", "stream-closed");
    }

    PROXY_LOG(Debug, "[client] H2 stream=" << stream_id << " 已关闭");
    return 0;
}

nghttp2_ssize ClientRuntime::select_padding(nghttp2_session* /*session*/,
                                             const nghttp2_frame* frame,
                                             size_t max_payloadlen, void* /*user_data*/) {
    return static_cast<nghttp2_ssize>(
        select_http2_padded_length(frame->hd.type, frame->hd.length, max_payloadlen));
}

// ─────────────────────────────────────────────────────────────────────────────
// Local pump
// ─────────────────────────────────────────────────────────────────────────────

void ClientRuntime::accept_and_pump_loop() {
    try {
    EventDispatcher dispatcher;
    if (!dispatcher.valid()) {
        io_error_ = "初始化本地事件分发器失败";
        running_  = false;
        return;
    }
    std::map<socket_t, std::pair<bool, bool>> watched;
    std::map<socket_t, std::shared_ptr<LocalStream>> socket_to_stream;  // Fast lookup index

    while (running_) {
        // Drain pending connection closures
        drain_pending_conn_close();

        // Retry any incomplete handshakes at the start of each iteration
        // This ensures fast processing of incoming handshake data
        retry_pending_handshakes();

        std::map<socket_t, std::pair<bool, bool>> desired;
        desired[listener_] = {true, false};
        desired[local_loop_notifier_.readable_socket()] = {true, false};

        // Add pending handshake sockets to watch list (wait for more data)
        for (const auto& handshake : pending_handshakes_) {
            desired[handshake.sock] = {true, false};  // readable, not writable
        }

        // Add HTTP connection sockets to watch list
        for (const auto& [sock, conn] : connections_) {
            bool wants_write = false;
            {
                std::lock_guard<std::mutex> lk(conn->mutex);
                if (!conn->stream_queue.empty()) {
                    auto front = conn->stream_queue.front();
                    std::lock_guard<std::mutex> sl(front->mutex);
                    wants_write = front->pending_downlink_offset < front->pending_downlink.size();
                }
            }
            desired[sock] = {true, wants_write};
        }

        std::vector<std::shared_ptr<LocalStream>> snapshot;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            for (const auto& kv : streams_) snapshot.push_back(kv.second);
        }

        // Rebuild fast lookup index for this iteration
        socket_to_stream.clear();
        for (const auto& stream : snapshot) {
            std::lock_guard<std::mutex> sl(stream->mutex);
            if (stream->state == LocalStream::State::Open &&
                stream->sock != kInvalidSocket) {
                socket_to_stream[stream->sock] = stream;
            }
        }

        for (const auto& stream : snapshot) {
            socket_t sock     = kInvalidSocket;
            bool wants_write  = false;
            {
                std::lock_guard<std::mutex> sl(stream->mutex);
                if (stream->state != LocalStream::State::Open ||
                    stream->sock == kInvalidSocket) continue;
                sock        = stream->sock;
                wants_write = stream->pending_downlink_offset
                              < stream->pending_downlink.size();
            }
            desired[sock] = {true, wants_write};
        }

        std::string de;
        for (auto it = watched.begin(); it != watched.end();) {
            if (desired.find(it->first) == desired.end()) {
                dispatcher.remove(it->first, de);
                it = watched.erase(it);
            } else { ++it; }
        }
        for (const auto& kv : desired) {
            const auto it = watched.find(kv.first);
            if (it == watched.end() || it->second != kv.second) {
                if (!dispatcher.set(kv.first, kv.second.first, kv.second.second, de)) {
                    io_error_ = de; running_ = false; return;
                }
                watched[kv.first] = kv.second;
            }
        }

        std::vector<SocketEvent> events;
        const int ready = dispatcher.wait(events, -1, de);
        if (ready < 0) { io_error_ = de; running_ = false; return; }

        for (const auto& ev : events) {
            if (ev.sock == local_loop_notifier_.readable_socket()) {
                local_loop_notifier_.drain();
                continue;
            }
            if (ev.sock == listener_ && ev.readable) {
                accept_one();
                // Retry any pending handshakes after accepting new connections
                retry_pending_handshakes();
                continue;
            }

            // Check if this event is for a pending handshake socket
            bool is_pending_handshake = false;
            for (const auto& hs : pending_handshakes_) {
                if (hs.sock == ev.sock) {
                    is_pending_handshake = true;
                    break;
                }
            }
            if (is_pending_handshake) {
                // Retry pending handshakes (will process this socket's event)
                retry_pending_handshakes();
                continue;
            }

            // Check if this event is for an HTTP connection socket
            auto conn_it = connections_.find(ev.sock);
            if (conn_it != connections_.end()) {
                auto& conn = conn_it->second;
                PROXY_LOG(Debug, "[client] accept_and_pump_loop: HTTP connection event"
                              << " readable=" << ev.readable << " writable=" << ev.writable
                              << " error=" << ev.error << " hangup=" << ev.hangup);
                if (ev.error || ev.hangup) {
                    PROXY_LOG(Info, "[client] accept_and_pump_loop: closing connection due to error/hangup");
                    close_local_connection(conn);
                    continue;
                }
                if (ev.writable) {
                    std::string err;
                    PROXY_LOG(Debug, "[client] accept_and_pump_loop: flushing downlink data");
                    flush_local_connection(conn, err);
                    if (!err.empty()) {
                        PROXY_LOG(Debug, "[client] flush error: " << err);
                        close_local_connection(conn);
                    }
                }
                if (ev.readable) {
                    PROXY_LOG(Debug, "[client] accept_and_pump_loop: calling pump_local_connection");
                    pump_local_connection(conn);
                }
                continue;
            }

            // Find target stream - verify index lookup and check stream state
            std::shared_ptr<LocalStream> target;
            {
                // First try fast lookup
                auto it = socket_to_stream.find(ev.sock);
                if (it != socket_to_stream.end()) {
                    target = it->second;
                    // Verify stream is still valid (not closed/modified)
                    std::lock_guard<std::mutex> sl(target->mutex);
                    if (target->state != LocalStream::State::Open ||
                        target->sock != ev.sock) {
                        target = nullptr;  // Stream state changed, discard
                    }
                }
            }

            // Fallback to linear search if fast lookup failed or returned invalid stream
            if (!target) {
                for (const auto& stream : snapshot) {
                    std::lock_guard<std::mutex> sl(stream->mutex);
                    if (stream->state == LocalStream::State::Open &&
                        stream->sock == ev.sock) {
                        target = stream;
                        break;
                    }
                }
            }

            if (!target) continue;

            if ((ev.error || ev.hangup) && !ev.writable) {
                close_local_stream(target);
                continue;
            }
            if (ev.writable) {
                std::string err;
                if (!flush_local_socket(target, err)) {
                    PROXY_LOG(Debug, "[client] 刷新本地下行失败 stream="
                              << target->h2_stream_id << " " << err);
                    close_local_stream(target);
                    continue;
                }
            }
            if (ev.readable) {
                // Re-check state under lock
                bool still_open = false;
                {
                    std::lock_guard<std::mutex> sl(target->mutex);
                    still_open = (target->state == LocalStream::State::Open &&
                                  target->sock != kInvalidSocket);
                }
                if (still_open) pump_local_socket(target);
            }
        }
    }
    PROXY_LOG(Warn, "[client] 本地转发循环结束"
              << (io_error_.empty() ? "" : " reason=" + io_error_));
    } catch (const std::exception& ex) {
        io_error_ = std::string("accept_and_pump_loop 未捕获异常: ") + ex.what();
        PROXY_LOG(Error, "[client] " << io_error_);
        running_ = false;
    } catch (...) {
        io_error_ = "accept_and_pump_loop 未捕获未知异常";
        PROXY_LOG(Error, "[client] " << io_error_);
        running_ = false;
    }
}

void ClientRuntime::accept_one() {
    sockaddr_storage ss{};
    socklen_t slen = sizeof(ss);
    socket_t sock = ::accept(listener_, reinterpret_cast<sockaddr*>(&ss), &slen);
    if (sock == kInvalidSocket) return;

    // 设置非阻塞模式，握手由 pump thread 异步处理
    std::string err;
    if (!proxy::set_socket_nonblocking(sock, true, err)) {
        PROXY_LOG(Error, "[client] 设置非阻塞失败: " << err);
        close_socket(sock);
        return;
    }

    // 添加到待握手队列，由 pump thread 异步处理
    pending_handshakes_.push_back(PendingHandshake{sock, {}});
    PROXY_LOG(Debug, "[client] 接受新连接，等待握手数据");
}

void ClientRuntime::retry_pending_handshakes() {
    // Try to complete any pending handshakes (non-blocking)
    for (auto it = pending_handshakes_.begin(); it != pending_handshakes_.end(); ) {
        auto& handshake = *it;
        const int max_header_bytes = 64 * 1024;

        // Try to read more data from the socket (non-blocking)
        std::array<char, 4096> buf{};
        int ret = 0;
#ifdef _WIN32
        ret = ::recv(handshake.sock, buf.data(), static_cast<int>(buf.size()), 0);
#else
        ret = static_cast<int>(::recv(handshake.sock, buf.data(), buf.size(), 0));
#endif

        bool should_erase = false;
        if (ret > 0) {
            // Received data, accumulate it
            handshake.raw_request.append(buf.data(), static_cast<std::size_t>(ret));
        } else if (ret == 0) {
            // Connection closed
            PROXY_LOG(Debug, "[client] 握手期间客户端断开连接");
            close_socket(handshake.sock);
            should_erase = true;
        } else {
            // ret < 0: either EAGAIN (no data yet) or error
            int errno_val = proxy::last_socket_error_code();
            if (!is_socket_would_block(errno_val)) {
                // Real error, not just "would block"
                PROXY_LOG(Debug, "[client] 握手期间读取失败: errno=" << errno_val);
                close_socket(handshake.sock);
                should_erase = true;
            }
            // else: EAGAIN, just wait for more data
        }

        // Check if we have complete HTTP headers
        const std::size_t header_end = handshake.raw_request.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            // Headers are complete, try to parse
            // Create a temporary socket just for parsing (read-only)
            AcceptedProxyRequest accepted;
            std::string parse_error;

            // We need to manually parse since recv_http_headers() does blocking recv
            // Just validate the headers are there
            {
                std::istringstream stream(handshake.raw_request.substr(0, header_end));
                std::string request_line;
                if (std::getline(stream, request_line)) {
                    if (!request_line.empty() && request_line.back() == '\r') {
                        request_line.pop_back();
                    }

                    // Parse using the existing parse_http_proxy_request but with data we already have
                    // We'll use a workaround: create a fake recv that returns our buffered data
                    std::istringstream rls(request_line);
                    std::string method, target_text, version;
                    rls >> method >> target_text >> version;

                    if (!method.empty() && !target_text.empty() && !version.empty()) {
                        // Basic validation passed, now do full parse
                        // For now, we'll close the socket temporarily and re-parse
                        // This is not ideal but keeps us safe

                        // Actually, let's just try to parse what we have
                        std::vector<std::pair<std::string, std::string>> headers;
                        std::string host_header;
                        for (std::string line; std::getline(stream, line);) {
                            if (!line.empty() && line.back() == '\r') line.pop_back();
                            if (line.empty()) continue;
                            const auto colon = line.find(':');
                            if (colon == std::string::npos) {
                                parse_error = "HTTP 请求头格式错误";
                                break;
                            }
                            std::string name = trim_ascii(line.substr(0, colon));
                            std::string value = trim_ascii(line.substr(colon + 1));
                            if (ascii_lower(name) == "host") host_header = value;
                            headers.emplace_back(std::move(name), std::move(value));
                        }

                        if (parse_error.empty()) {
                            Socks5Request req;
                            if (ascii_lower(method) == "connect") {
                                // CONNECT request
                                if (!parse_host_port(target_text, req.host, req.port)) {
                                    const auto c = target_text.rfind(':');
                                    if (c != std::string::npos) {
                                        req.host = target_text.substr(0, c);
                                        req.port = static_cast<std::uint16_t>(std::stoi(target_text.substr(c + 1)));
                                    } else {
                                        parse_error = "CONNECT 缺少目标端口";
                                    }
                                }
                                if (parse_error.empty()) {
                                    req.atyp = detect_atyp_from_host(req.host);
                                    accepted.target = std::move(req);
                                    accepted.protocol = LocalProxyProtocol::HttpConnect;
                                    accepted.initial_payload.clear();
                                }
                            } else {
                                // HTTP Forward request
                                std::string remote_host;
                                std::uint16_t remote_port = 80;
                                std::string request_target = target_text;
                                const std::string lowered_target = ascii_lower(target_text);
                                if (lowered_target.rfind("http://", 0) == 0) {
                                    const std::string authority_and_path = target_text.substr(7);
                                    const auto slash = authority_and_path.find('/');
                                    const std::string authority = slash == std::string::npos
                                        ? authority_and_path : authority_and_path.substr(0, slash);
                                    request_target = slash == std::string::npos ? "/" : authority_and_path.substr(slash);
                                    if (!parse_host_port(authority, remote_host, remote_port)) {
                                        remote_host = authority; remote_port = 80;
                                    }
                                } else {
                                    if (host_header.empty()) {
                                        parse_error = "HTTP 代理请求缺少 Host";
                                    } else if (!parse_host_port(host_header, remote_host, remote_port)) {
                                        remote_host = host_header; remote_port = 80;
                                    }
                                }
                                if (parse_error.empty() && !remote_host.empty()) {
                                    req.host = remote_host;
                                    req.port = remote_port;
                                    req.atyp = detect_atyp_from_host(req.host);

                                    std::ostringstream rebuilt;
                                    rebuilt << method << " " << request_target << " " << version << "\r\n";
                                    bool has_host = false;
                                    for (const auto& header : headers) {
                                        const std::string lower_name = ascii_lower(header.first);
                                        if (lower_name == "proxy-connection") continue;
                                        if (lower_name == "host") has_host = true;
                                        rebuilt << header.first << ": " << header.second << "\r\n";
                                    }
                                    if (!has_host) {
                                        rebuilt << "Host: " << remote_host;
                                        if (remote_port != 80) rebuilt << ":" << remote_port;
                                        rebuilt << "\r\n";
                                    }
                                    rebuilt << "\r\n";

                                    accepted.target = std::move(req);
                                    accepted.protocol = LocalProxyProtocol::HttpForward;
                                    const std::string rebuilt_request = rebuilt.str();
                                    accepted.initial_payload.assign(rebuilt_request.begin(), rebuilt_request.end());
                                    const std::size_t body_offset = header_end + 4;
                                    if (body_offset < handshake.raw_request.size()) {
                                        accepted.initial_payload.insert(accepted.initial_payload.end(),
                                                                        handshake.raw_request.begin() + static_cast<std::ptrdiff_t>(body_offset),
                                                                        handshake.raw_request.end());
                                    }
                                } else if (parse_error.empty()) {
                                    parse_error = "无法解析 HTTP 目标主机";
                                }
                            }
                        }
                    } else {
                        parse_error = "HTTP 请求行格式错误";
                    }
                } else {
                    parse_error = "HTTP 请求行为空";
                }
            }

            if (parse_error.empty()) {
                // Handshake successful
                PROXY_LOG(Info, "[client] 握手完成 target=" << describe_socks5_target(accepted.target)
                          << " proto=" << (accepted.protocol == LocalProxyProtocol::HttpConnect ? "http-connect"
                                                                                                : "http"));

                // For HTTP (CONNECT and Forward): use new LocalConnection path
                if (accepted.protocol == LocalProxyProtocol::HttpConnect ||
                    accepted.protocol == LocalProxyProtocol::HttpForward) {
                    // Create new LocalConnection for this socket
                    auto conn = std::make_shared<LocalConnection>();
                    conn->sock = handshake.sock;
                    conn->is_connect_mode = false;
                    conn->recv_buf.assign(handshake.raw_request.begin(), handshake.raw_request.end());

                    PROXY_LOG(Info, "[client] created LocalConnection for HTTP request, "
                              << "buf_size=" << conn->recv_buf.size()
                              << " protocol=" << (accepted.protocol == LocalProxyProtocol::HttpConnect ? "CONNECT" : "FORWARD"));

                    // Add to connections map
                    connections_[handshake.sock] = conn;

                    // Immediately process buffered HTTP request (we're in pump thread, safe to do)
                    // This ensures the request gets parsed and H2 stream created even if socket
                    // won't become readable again (client is waiting for response)
                    PROXY_LOG(Info, "[client] calling pump_local_connection immediately after handshake");
                    pump_local_connection(conn);

                    // Signal in case more processing is needed
                    signal_notifier(local_loop_notifier_, "client", "new-conn");
                    should_erase = true;
                } else {
                    // SOCKS5 path: use old pending_tunnels_ mechanism
                    {
                        std::lock_guard<std::mutex> lock(pending_mutex_);
                        PendingTunnel pt;
                        pt.sock = handshake.sock;  // SOCKS5 path
                        pt.target = accepted.target;
                        pt.protocol = accepted.protocol;
                        pt.initial_payload = std::move(accepted.initial_payload);
                        pending_tunnels_.push_back(pt);
                    }
                    signal_notifier(io_notifier_, "client", "new-tunnel");
                    should_erase = true;
                }
            } else {
                // Parse error
                PROXY_LOG(Warn, "[client] 握手解析失败: " << parse_error);
                send_http_proxy_response(handshake.sock, 400, "Bad Request", parse_error);
                close_socket(handshake.sock);
                should_erase = true;
            }
        } else if (handshake.raw_request.size() > max_header_bytes) {
            // Headers too large
            PROXY_LOG(Warn, "[client] HTTP 请求头过大");
            send_http_proxy_response(handshake.sock, 400, "Bad Request", "headers too large");
            close_socket(handshake.sock);
            should_erase = true;
        }

        if (should_erase) {
            it = pending_handshakes_.erase(it);
        } else {
            ++it;
        }
    }
}

void ClientRuntime::pump_local_socket(const std::shared_ptr<LocalStream>& stream) {
    socket_t sock = kInvalidSocket;
    int32_t h2_stream_id = -1;

    // Check stream state and get socket (hold lock briefly)
    {
        std::lock_guard<std::mutex> sl(stream->mutex);
        if (stream->state != LocalStream::State::Open || stream->sock == kInvalidSocket) {
            return;
        }
        // Check backpressure: don't read if buffer is full
        if (stream->pending_uplink.size() >= kMaxUplinkBuffer) {
            return;  // Buffer full, stop reading
        }
        sock = stream->sock;
        h2_stream_id = stream->h2_stream_id;
    }

    // Perform recv() without holding lock
    std::array<std::uint8_t, kTunnelIoChunkSize> buf{};
#ifdef _WIN32
    const int ret = ::recv(sock, reinterpret_cast<char*>(buf.data()),
                           static_cast<int>(buf.size()), 0);
#else
    const int ret = static_cast<int>(::recv(sock, buf.data(), buf.size(), 0));
#endif

    // Check if recv failed or socket would block
    if (ret < 0 && is_socket_would_block(proxy::last_socket_error_code())) {
        return;
    }

    // Handle recv errors and EOF
    if (ret <= 0) {
        // Verify stream still exists and hasn't been closed yet
        std::lock_guard<std::mutex> sl(stream->mutex);
        if (stream->state == LocalStream::State::Open && stream->sock == sock) {
            close_local_stream(stream);
        }
        return;
    }

    PROXY_LOG(Debug, "[client] stream=" << h2_stream_id
              << " 读取本地上行数据 bytes=" << ret);

    // Buffer the data (hold lock only briefly)
    bool need_resume = false;
    {
        std::lock_guard<std::mutex> sl(stream->mutex);
        // Verify stream still valid before buffering
        if (stream->state != LocalStream::State::Open ||
            stream->sock != sock ||
            h2_stream_id != stream->h2_stream_id) {
            return;  // Stream state changed, discard data
        }

        stream->pending_uplink.insert(stream->pending_uplink.end(),
                                      buf.data(), buf.data() + ret);
        need_resume = stream->uplink_deferred;
    }

    if (need_resume) {
        {
            std::lock_guard<std::mutex> lock(resume_mutex_);
            pending_resume_.insert(h2_stream_id);
        }
        signal_notifier(io_notifier_, "client", "uplink-data");
    }
}

bool ClientRuntime::flush_local_socket(const std::shared_ptr<LocalStream>& stream,
                                        std::string& error) {
    std::lock_guard<std::mutex> sl(stream->mutex);
    if (stream->state != LocalStream::State::Open || stream->sock == kInvalidSocket) return true;

    while (stream->pending_downlink_offset < stream->pending_downlink.size()) {
        const auto* data = stream->pending_downlink.data() + stream->pending_downlink_offset;
        const std::size_t remaining = stream->pending_downlink.size()
                                    - stream->pending_downlink_offset;
#ifdef _WIN32
        const int ret = ::send(stream->sock, reinterpret_cast<const char*>(data),
                               static_cast<int>(remaining), 0);
#else
        const int ret = static_cast<int>(::send(stream->sock, data, remaining, 0));
#endif
        if (ret > 0) {
            stream->pending_downlink_offset += static_cast<std::size_t>(ret);
            continue;
        }
        if (ret < 0 && is_socket_would_block(proxy::last_socket_error_code())) break;
        error = "socket send 失败: " + proxy::socket_error_string();
        return false;
    }

    if (stream->pending_downlink_offset >= stream->pending_downlink.size()) {
        stream->pending_downlink.clear();
        stream->pending_downlink_offset = 0;
    } else if (stream->pending_downlink_offset >= kTunnelIoChunkSize) {
        // Optimized cleanup: move remaining data to front instead of erasing
        const std::size_t remaining = stream->pending_downlink.size()
                                    - stream->pending_downlink_offset;
        std::memmove(stream->pending_downlink.data(),
                     stream->pending_downlink.data() + stream->pending_downlink_offset,
                     remaining);
        stream->pending_downlink.resize(remaining);
        stream->pending_downlink_offset = 0;
    }
    return true;
}

void ClientRuntime::close_local_stream(const std::shared_ptr<LocalStream>& stream) {
    socket_t sock = kInvalidSocket;
    int32_t h2sid = -1;
    bool need_resume = false;
    {
        std::lock_guard<std::mutex> sl(stream->mutex);
        if (stream->sock == kInvalidSocket) return;  // already closed
        sock          = stream->sock;
        stream->sock  = kInvalidSocket;
        h2sid         = stream->h2_stream_id;
        stream->uplink_eof = true;
        need_resume   = stream->uplink_deferred;
    }
    if (sock != kInvalidSocket) close_socket(sock);

    // Wake io_thread to send END_STREAM via data provider
    if (need_resume && h2sid >= 0) {
        {
            std::lock_guard<std::mutex> lock(resume_mutex_);
            pending_resume_.insert(h2sid);
        }
        signal_notifier(io_notifier_, "client", "local-eof");
    }
    signal_notifier(local_loop_notifier_, "client", "local-closed");
}

void ClientRuntime::drain_pending_conn_close() {
    std::deque<std::shared_ptr<LocalConnection>> to_close;
    {
        std::lock_guard<std::mutex> lk(conn_close_mutex_);
        to_close.swap(pending_conn_close_);
    }

    for (auto& conn : to_close) {
        if (conn && conn->sock != kInvalidSocket) {
            close_socket(conn->sock);
            connections_.erase(conn->sock);
        }
    }
}

void ClientRuntime::pump_local_connection(const std::shared_ptr<LocalConnection>& conn) {
    if (!conn || conn->sock == kInvalidSocket) return;

    // Try to receive new data from socket
    {
        std::array<uint8_t, kTunnelIoChunkSize> buf{};
#ifdef _WIN32
        const int ret = ::recv(conn->sock, reinterpret_cast<char*>(buf.data()),
                               static_cast<int>(buf.size()), 0);
#else
        const int ret = static_cast<int>(::recv(conn->sock, buf.data(), buf.size(), 0));
#endif

        if (ret > 0) {
            // Buffer the received data
            std::lock_guard<std::mutex> lk(conn->mutex);
            PROXY_LOG(Debug, "[client] pump_local_connection: received " << ret << " bytes from socket"
                          << " is_connect_mode=" << conn->is_connect_mode
                          << " stream_queue_size=" << conn->stream_queue.size());
            conn->recv_buf.insert(conn->recv_buf.end(), buf.data(), buf.data() + ret);
        } else if (ret == 0) {
            // EOF from socket
            std::lock_guard<std::mutex> lk(conn->mutex);
            PROXY_LOG(Info, "[client] pump_local_connection: socket EOF");
            conn->recv_eof = true;
        } else if (ret < 0 && !is_socket_would_block(proxy::last_socket_error_code())) {
            // Real error (not EAGAIN)
            std::lock_guard<std::mutex> lk(conn->mutex);
            PROXY_LOG(Error, "[client] pump_local_connection: socket error");
            conn->recv_eof = true;
        }
        // If EAGAIN, just continue with processing buffered data
    }

    // Process buffered data
    while (true) {
        // Check what processing is needed (under lock)
        bool should_process_connect = false;
        bool should_process_body = false;
        bool should_parse_request = false;
        std::shared_ptr<LocalStream> active_stream;
        std::size_t body_remaining = 0;
        std::size_t recv_buf_size = 0;

        {
            std::lock_guard<std::mutex> lk(conn->mutex);

            recv_buf_size = conn->recv_buf.size();

            // If in CONNECT mode or pipeline broken, pass all bytes to active stream
            if (conn->is_connect_mode || conn->pipeline_broken) {
                should_process_connect = !conn->stream_queue.empty() && !conn->recv_buf.empty();
            } else if (conn->body_remaining > 0) {
                // Forward mode: route bytes to current request stream
                should_process_body = conn->active_recv_stream && !conn->recv_buf.empty();
                active_stream = conn->active_recv_stream;
                body_remaining = conn->body_remaining;
            } else {
                // At request boundary: try to parse next request
                should_parse_request = !conn->recv_buf.empty();
            }
        }

        // Process outside the lock to avoid deadlock
        if (should_process_connect) {
            std::lock_guard<std::mutex> lk(conn->mutex);
            if (!conn->stream_queue.empty() && !conn->recv_buf.empty()) {
                auto stream = conn->stream_queue.front();
                {
                    std::lock_guard<std::mutex> sl(stream->mutex);
                    const std::size_t data_size = conn->recv_buf.size();
                    PROXY_LOG(Info, "[client] CONNECT mode: forwarding " << data_size << " bytes to stream"
                                  << " h2_stream_id=" << stream->h2_stream_id
                                  << " state=" << static_cast<int>(stream->state)
                                  << " uplink_deferred=" << stream->uplink_deferred);
                    stream->pending_uplink.insert(stream->pending_uplink.end(),
                                                  conn->recv_buf.begin(), conn->recv_buf.end());
                    bool should_resume = stream->uplink_deferred;
                    conn->recv_buf.clear();
                    if (should_resume) {
                        PROXY_LOG(Debug, "[client] CONNECT mode: resuming deferred uplink for stream=" << stream->h2_stream_id);
                        std::lock_guard<std::mutex> rl(resume_mutex_);
                        pending_resume_.insert(stream->h2_stream_id);
                    }
                }
                signal_notifier(io_notifier_, "client", "uplink-data");
            } else {
                PROXY_LOG(Debug, "[client] CONNECT mode: cannot process - queue_empty=" << conn->stream_queue.empty()
                              << " buf_empty=" << conn->recv_buf.empty());
            }
            break;
        }

        if (should_process_body && active_stream) {
            std::size_t to_send = 0;
            {
                std::lock_guard<std::mutex> lk(conn->mutex);
                to_send = std::min(conn->body_remaining, conn->recv_buf.size());
            }

            if (to_send > 0) {
                {
                    std::lock_guard<std::mutex> sl(active_stream->mutex);
                    active_stream->pending_uplink.insert(active_stream->pending_uplink.end(),
                                                  conn->recv_buf.begin(),
                                                  conn->recv_buf.begin() + to_send);
                    bool should_resume = active_stream->uplink_deferred;
                    if (should_resume) {
                        std::lock_guard<std::mutex> rl(resume_mutex_);
                        pending_resume_.insert(active_stream->h2_stream_id);
                    }
                }
                {
                    std::lock_guard<std::mutex> lk(conn->mutex);
                    conn->body_remaining -= to_send;
                    conn->recv_buf.erase(conn->recv_buf.begin(), conn->recv_buf.begin() + to_send);
                }
                signal_notifier(io_notifier_, "client", "uplink-data");

                if (conn->body_remaining > 0) break;  // Wait for more data
            } else {
                break;
            }
            continue;
        }

        if (should_parse_request && recv_buf_size > 0) {
            auto new_stream = try_parse_next_request(conn);
            if (!new_stream) break;  // Incomplete headers or parse error
            {
                std::lock_guard<std::mutex> lk(conn->mutex);
                conn->active_recv_stream = new_stream;
            }
            continue;
        }

        break;
    }
}

bool ClientRuntime::flush_local_connection(const std::shared_ptr<LocalConnection>& conn,
                                             std::string& error) {
    if (!conn || conn->sock == kInvalidSocket) return true;

    std::lock_guard<std::mutex> lk(conn->mutex);
    if (conn->stream_queue.empty()) return true;

    // Only flush the head-of-queue stream to enforce HTTP/1.1 pipelining order
    auto front = conn->stream_queue.front();

    std::lock_guard<std::mutex> sl(front->mutex);
    if (front->state != LocalStream::State::Open) {
        return true;
    }
    // For HTTP paths, stream owns socket via connection, not directly
    // So don't check front->sock == kInvalidSocket for HTTP streams

    // Send pending downlink data to socket
    while (front->pending_downlink_offset < front->pending_downlink.size()) {
        const auto* data = front->pending_downlink.data() + front->pending_downlink_offset;
        const std::size_t remaining = front->pending_downlink.size() - front->pending_downlink_offset;

#ifdef _WIN32
        const int ret = ::send(conn->sock, reinterpret_cast<const char*>(data),
                               static_cast<int>(remaining), 0);
#else
        const int ret = static_cast<int>(::send(conn->sock, data, remaining, 0));
#endif
        if (ret > 0) {
            front->pending_downlink_offset += ret;
            continue;
        }
        if (ret < 0 && is_socket_would_block(proxy::last_socket_error_code())) {
            break;  // EAGAIN: socket buffer full
        }
        error = "socket send failed: " + proxy::socket_error_string();
        return false;
    }

    // If fully flushed, clear the buffer
    if (front->pending_downlink_offset >= front->pending_downlink.size()) {
        front->pending_downlink.clear();
        front->pending_downlink_offset = 0;
    } else if (front->pending_downlink_offset >= kTunnelIoChunkSize) {
        // Optimization: move remaining data to front
        const std::size_t remaining = front->pending_downlink.size() - front->pending_downlink_offset;
        if (remaining > 0) {
            std::memmove(front->pending_downlink.data(),
                         front->pending_downlink.data() + front->pending_downlink_offset,
                         remaining);
        }
        front->pending_downlink.resize(remaining);
        front->pending_downlink_offset = 0;
    }

    return true;
}

void ClientRuntime::close_local_connection(const std::shared_ptr<LocalConnection>& conn) {
    if (!conn) return;

    socket_t sock = kInvalidSocket;
    {
        std::lock_guard<std::mutex> lk(conn->mutex);
        sock = conn->sock;

        // Close all streams in the queue
        for (auto& stream : conn->stream_queue) {
            std::lock_guard<std::mutex> sl(stream->mutex);
            stream->state = LocalStream::State::Closed;
            stream->uplink_eof = true;
            stream->sock = kInvalidSocket;
        }
        conn->stream_queue.clear();
        conn->recv_buf.clear();
    }

    // Close socket
    if (sock != kInvalidSocket) {
        close_socket(sock);
        connections_.erase(sock);
    }
}

std::shared_ptr<LocalStream> ClientRuntime::try_parse_next_request(
    const std::shared_ptr<LocalConnection>& conn) {
    if (!conn) {
        PROXY_LOG(Warn, "[client] try_parse_next_request: conn is nullptr");
        return nullptr;
    }

    std::lock_guard<std::mutex> lk(conn->mutex);
    if (conn->recv_buf.empty()) {
        PROXY_LOG(Debug, "[client] try_parse_next_request: recv_buf is empty");
        return nullptr;
    }

    PROXY_LOG(Debug, "[client] try_parse_next_request: parsing "
              << conn->recv_buf.size() << " bytes");

    // Parse HTTP request boundary from buffer
    HttpRequestBoundary boundary;
    if (!parse_http_boundary(conn->recv_buf, boundary)) {
        PROXY_LOG(Debug, "[client] try_parse_next_request: parse_http_boundary returned false (incomplete?)");
        return nullptr;  // Headers not complete yet
    }

    PROXY_LOG(Info, "[client] try_parse_next_request: parsed request method='"
              << boundary.method << "' target='" << boundary.remote_host << ":" << boundary.remote_port << "'");

    // For chunked or keep-alive=false: fall back to non-pipelined mode
    if (boundary.chunked || !boundary.keep_alive) {
        conn->pipeline_broken = true;
    }

    // Extract request data from buffer
    const std::size_t request_len = boundary.header_len + boundary.body_len;
    if (conn->recv_buf.size() < request_len) {
        return nullptr;  // Body not complete yet
    }

    // Create a new LocalStream for this request
    auto stream = std::make_shared<LocalStream>();
    stream->h2_stream_id = -1;
    stream->sock = kInvalidSocket;  // Will be set to null (stream doesn't own socket)
    stream->conn = conn;
    stream->protocol = LocalProxyProtocol::HttpConnect;  // Default: will be overridden
    stream->state = LocalStream::State::Pending;

    // Parse the HTTP request
    std::istringstream req_stream(std::string(reinterpret_cast<const char*>(conn->recv_buf.data()),
                                              boundary.header_len));
    std::string line;
    std::string method, target, version;

    // Request line
    if (!std::getline(req_stream, line) || line.size() < 2) {
        return nullptr;
    }
    if (line.back() == '\r') line.pop_back();
    {
        std::istringstream rls(line);
        if (!(rls >> method >> target >> version)) {
            return nullptr;
        }
    }

    // Parse headers to determine protocol
    Socks5Request socks_req;
    bool is_connect = (ascii_lower(method) == "connect");

    // Security: if socket is already in CONNECT mode, reject new requests
    if (is_connect && conn->is_connect_mode) {
        PROXY_LOG(Warn, "[client] try_parse_next_request: rejecting CONNECT on already-CONNECT socket");
        return nullptr;
    }

    if (is_connect) {
        // CONNECT target:port
        const auto colon = target.rfind(':');
        if (colon == std::string::npos) {
            return nullptr;  // Invalid CONNECT
        }
        socks_req.host = target.substr(0, colon);
        try {
            socks_req.port = std::stoi(target.substr(colon + 1));
        } catch (...) {
            return nullptr;
        }
        socks_req.atyp = detect_atyp_from_host(socks_req.host);
        stream->protocol = LocalProxyProtocol::HttpConnect;
    } else {
        // HTTP Forward (GET/POST/etc)
        // Extract Host header
        std::string host_header;
        std::string lowered_target = ascii_lower(target);

        if (lowered_target.rfind("http://", 0) == 0) {
            // Absolute URI
            const std::string authority_and_path = target.substr(7);
            const auto slash = authority_and_path.find('/');
            host_header = (slash == std::string::npos) ? authority_and_path
                                                        : authority_and_path.substr(0, slash);
        } else {
            // Relative URI - need Host header
            for (std::string hdr; std::getline(req_stream, hdr);) {
                if (hdr.size() >= 2 && hdr.back() == '\r') hdr.pop_back();
                if (hdr.empty()) break;

                const auto colon = hdr.find(':');
                if (colon != std::string::npos) {
                    std::string hname = hdr.substr(0, colon);
                    if (ascii_lower(hname) == "host") {
                        host_header = hdr.substr(colon + 1);
                        // Trim leading whitespace
                        while (!host_header.empty() && std::isspace(host_header[0])) {
                            host_header = host_header.substr(1);
                        }
                        break;
                    }
                }
            }
        }

        if (host_header.empty()) {
            return nullptr;
        }

        // Parse host:port
        const auto colon = host_header.rfind(':');
        if (colon != std::string::npos) {
            socks_req.host = host_header.substr(0, colon);
            try {
                socks_req.port = std::stoi(host_header.substr(colon + 1));
            } catch (...) {
                socks_req.host = host_header;
                socks_req.port = 80;
            }
        } else {
            socks_req.host = host_header;
            socks_req.port = 80;
        }
        socks_req.atyp = detect_atyp_from_host(socks_req.host);
        stream->protocol = LocalProxyProtocol::HttpForward;

        // For forward mode: store the original request as initial_payload
        stream->initial_payload.assign(conn->recv_buf.begin(),
                                       conn->recv_buf.begin() + request_len);
    }

    // Create PendingTunnel and queue it
    {
        std::lock_guard<std::mutex> tl(pending_mutex_);
        PendingTunnel pt;
        pt.conn = conn;
        pt.target = socks_req;
        pt.protocol = stream->protocol;
        pt.initial_payload = std::move(stream->initial_payload);
        pending_tunnels_.push_back(pt);
    }

    // NOTE: Stream will be added to connection queue by process_pending_tunnels
    // after h2_stream_id is assigned. This avoids race condition where pump thread
    // tries to forward data before stream is submitted to nghttp2.

    // Remove request from recv_buf and set up body_remaining
    conn->recv_buf.erase(conn->recv_buf.begin(), conn->recv_buf.begin() + request_len);
    conn->body_remaining = 0;  // At boundary: ready to parse next

    // Signal IO thread
    signal_notifier(io_notifier_, "client", "new-tunnel");

    return stream;
}

void ClientRuntime::close_all_streams() {
    // Close all streams (SOCKS5 path)
    std::map<int32_t, std::shared_ptr<LocalStream>> current;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        current.swap(streams_);
    }
    for (auto& kv : current) {
        socket_t sock = kInvalidSocket;
        {
            std::lock_guard<std::mutex> sl(kv.second->mutex);
            sock              = kv.second->sock;
            kv.second->sock   = kInvalidSocket;
            kv.second->state  = LocalStream::State::Closed;
            kv.second->uplink_eof = true;
        }
        if (sock != kInvalidSocket) close_socket(sock);
    }

    // Close all HTTP connections
    auto conns = connections_;  // Copy map
    for (auto& [sock, conn] : conns) {
        close_local_connection(conn);
    }
}

socket_t ClientRuntime::make_listener(std::uint16_t port, std::string host) {
    socket_t sock = static_cast<socket_t>(::socket(AF_INET, SOCK_STREAM, 0));
    if (sock == kInvalidSocket) return kInvalidSocket;
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (host.empty() || host == "localhost" || host == "127.0.0.1") {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else if (host == "0.0.0.0" || host == "*") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close_socket(sock); return kInvalidSocket;
    }
    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(sock); return kInvalidSocket;
    }
    if (::listen(sock, 128) != 0) {
        close_socket(sock); return kInvalidSocket;
    }
    return sock;
}

ClientConfig parse_args(int argc, char** argv) {
    ClientConfig cfg;
    if (argc >= 2) parse_host_port(argv[1], cfg.server_host, cfg.server_port);
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if      (arg == "--listen"          && i + 1 < argc)
            cfg.listen_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        else if (arg == "--listen-host"     && i + 1 < argc)
            cfg.listen_host = argv[++i];
        else if (arg == "--auth-password"   && i + 1 < argc)
            cfg.auth_password = argv[++i];
        else if (arg == "--ech-config"      && i + 1 < argc)
            cfg.ech_config = argv[++i];
        else if (arg == "--disable-ech-grease")
            cfg.enable_ech_grease = false;
        else if (arg == "--log-level"       && i + 1 < argc) {
            LogLevel level = LogLevel::Info;
            if (parse_log_level(argv[++i], level)) cfg.log_level = level;
        }
    }
    return cfg;
}

void print_usage() {
    std::cout
        << "用法:\n"
        << "  client <server_host:port> [options]\n\n"
        << "选项:\n"
        << "  --listen <port>           本地代理监听端口, 默认 1080\n"
        << "  --listen-host <addr>      本地代理监听地址, 默认 127.0.0.1\n"
        << "  --auth-password <pw>      共享密码 (x-tunnel-auth 头)\n"
        << "  --ech-config <base64>     base64-encoded ECHConfigList\n"
        << "  --disable-ech-grease      关闭 ECH GREASE\n"
        << "  --log-level <level>       error|warn|info|debug, 默认 info\n\n"
        << "协议:\n"
        << "  每条本地连接对应一条 HTTP/2 CONNECT 流 (RFC 7540 §8.3)\n\n"
        << "示例:\n"
        << "  client 127.0.0.1:8443\n"
        << "  client example.com:8443 --listen 1088 --auth-password secret123\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { std::cerr << "WSAStartup 失败\n"; return 1; }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { print_usage(); return 0; }
    }

    const ClientConfig cfg = parse_args(argc, argv);
    set_log_level(cfg.log_level);
    if (cfg.server_host.empty()) { print_usage(); return 1; }

    const socket_t listener = ClientRuntime::make_listener(cfg.listen_port, cfg.listen_host);
    if (listener == kInvalidSocket) {
        PROXY_LOG(Error, "[client] 本地监听失败 port=" << cfg.listen_port);
        return 1;
    }
    struct ListenerCloser {
        socket_t sock;
        ~ListenerCloser() { if (sock != kInvalidSocket) close_socket(sock); }
    } lc{listener};

    int retry_attempt = 0;
    std::mt19937 rng(std::random_device{}());

    while (true) {
        ClientRuntime runtime(cfg, listener);
        if (runtime.start()) {
            PROXY_LOG(Info, "[client] runtime.start() 正常结束");
            return 0;
        }
        if (!runtime.should_retry()) {
            PROXY_LOG(Error, "[client] runtime.start() 返回失败");
            return 1;
        }

        // Reset backoff if connected successfully before
        if (runtime.was_connected()) {
            retry_attempt = 0;
        }

        // Exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s (capped)
        const int base_ms = std::min(1000 << retry_attempt, 30000);
        const int jitter_ms = base_ms * 20 / 100;  // ±20% jitter
        std::uniform_int_distribution<int> dist(-jitter_ms, jitter_ms);
        const int wait_ms = base_ms + dist(rng);

        PROXY_LOG(Warn, "[client] 隧道连接已断开，" << (wait_ms / 1000.0) << "s 后自动重连"
                  << " attempt=" << retry_attempt
                  << (runtime.last_error().empty() ? "" : " reason=" + runtime.last_error()));
        std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));

        if (retry_attempt < 5) retry_attempt++;
    }
    } catch (const std::exception& ex) {
        std::cerr << "[client] main 未捕获异常: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[client] main 未捕获未知异常\n";
        return 1;
    }
}
