#include "server_connection.h"

#include "common/logging.h"
#include "common/socks5.h"
#include "common/tunnel_protocol.h"
#include "homepage_html.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <map>
#include <sstream>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/socket.h>
#endif

namespace {

constexpr std::size_t kTunnelIoChunkSize = 256 * 1024;
constexpr std::size_t kSessionFlushBudgetBytes = 256 * 1024;
constexpr std::size_t kTlsWriteBudgetBytes = 256 * 1024;
constexpr std::size_t kTlsReadBudgetBytes = 256 * 1024;
constexpr std::size_t kHttp1ReadBudgetBytes = 16 * 1024;
constexpr std::size_t kUpstreamWriteBudgetBytes = 256 * 1024;
constexpr std::int32_t kHttp2WindowSize = 16 * 1024 * 1024;
constexpr std::uint32_t kHttp2MaxFrameSize = 1024 * 1024;

using proxy::close_socket;
using proxy::decode_open_request;
using proxy::encode_open_fail;
using proxy::encode_open_ok;
using proxy::EventFlags;
using proxy::FrameHeader;
using proxy::FrameType;
using proxy::kInvalidSocket;
using proxy::select_http2_padded_length;
using proxy::set_socket_nonblocking;
using proxy::socket_t;
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
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS;
#else
    return code == EAGAIN || code == EWOULDBLOCK || code == EINPROGRESS;
#endif
}

bool socket_connect_in_progress() {
#ifdef _WIN32
    const int code = WSAGetLastError();
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS || code == WSAEINVAL;
#else
    return errno == EINPROGRESS;
#endif
}

int socket_pending_error(socket_t sock) {
    int value = 0;
    socklen_t len = sizeof(value);
    if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&value), &len) != 0) {
#ifdef _WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }
    return value;
}

std::string socket_error_text(int code) {
#ifdef _WIN32
    return "socket error " + std::to_string(code);
#else
    return std::strerror(code);
#endif
}

std::vector<std::uint8_t> encode_socks5_connect_request(std::uint8_t atyp, const std::string& host,
                                                        std::uint16_t port) {
    std::vector<std::uint8_t> req = {0x05, 0x01, 0x00, atyp};
    if (atyp == 0x01) {
        in_addr ipv4{};
        if (::inet_pton(AF_INET, host.c_str(), &ipv4) != 1) return {};
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&ipv4);
        req.insert(req.end(), bytes, bytes + 4);
    } else if (atyp == 0x04) {
        in6_addr ipv6{};
        if (::inet_pton(AF_INET6, host.c_str(), &ipv6) != 1) return {};
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&ipv6);
        req.insert(req.end(), bytes, bytes + 16);
    } else {
        if (host.size() > 255) return {};
        req.push_back(static_cast<std::uint8_t>(host.size()));
        req.insert(req.end(), host.begin(), host.end());
    }
    req.push_back(static_cast<std::uint8_t>((port >> 8) & 0xff));
    req.push_back(static_cast<std::uint8_t>(port & 0xff));
    return req;
}

bool create_nonblocking_tcp_socket(const std::string& host, std::uint16_t port, socket_t& sock, bool& connected,
                                   std::string& error) {
    sock = kInvalidSocket;
    connected = false;
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* result = nullptr;
    const std::string port_text = std::to_string(port);
    const int gai_ret = ::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &result);
    if (gai_ret != 0) {
#ifdef _WIN32
        error = "getaddrinfo failed: " + std::to_string(gai_ret);
#else
        error = std::string("getaddrinfo failed: ") + gai_strerror(gai_ret);
#endif
        return false;
    }
    std::string nonblocking_error;
    for (addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
        socket_t candidate = static_cast<socket_t>(::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (candidate == kInvalidSocket) continue;
        if (!set_socket_nonblocking(candidate, true, nonblocking_error)) {
            close_socket(candidate);
            continue;
        }
        const int ret = ::connect(candidate, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (ret == 0) {
            sock = candidate;
            connected = true;
            freeaddrinfo(result);
            return true;
        }
        if (socket_connect_in_progress()) {
            sock = candidate;
            freeaddrinfo(result);
            return true;
        }
        error = proxy::socket_error_string();
        close_socket(candidate);
    }
    if (result != nullptr) freeaddrinfo(result);
    if (error.empty()) error = nonblocking_error.empty() ? "connect failed" : nonblocking_error;
    return false;
}

std::string homepage_html() { return generated::kHomepageHtml; }

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

struct Http1Request {
    std::string method;
    std::string path;
};

bool parse_http1_request(const std::string& buffer, Http1Request& request) {
    const auto line_end = buffer.find("\r\n");
    if (line_end == std::string::npos) return false;
    const std::string request_line = buffer.substr(0, line_end);
    std::istringstream line_stream(request_line);
    std::string version;
    return static_cast<bool>(line_stream >> request.method >> request.path >> version);
}

std::vector<std::uint8_t> build_http1_response(int status, const std::string& content_type,
                                               const std::vector<std::uint8_t>& body, bool homepage = false) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << (status == 200 ? " OK" : " ERROR") << "\r\n";
    oss << "Content-Type: " << content_type << "\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\nServer: nginx\r\n";
    oss << "Cache-Control: public, max-age=300\r\nVary: Accept-Encoding\r\n";
    oss << "X-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n";
    oss << "Referrer-Policy: strict-origin-when-cross-origin\r\n";
    if (homepage) oss << "Content-Language: en\r\n";
    oss << "\r\n";
    const std::string head = oss.str();
    std::vector<std::uint8_t> out(head.begin(), head.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

} // namespace

ServerConnection::ServerConnection(socket_t accepted_socket, ServerConfig config)
    : accepted_socket_(accepted_socket), config_(std::move(config)), mode_(Mode::Closed) {}

ServerConnection::~ServerConnection() {
    close_all_upstreams();
    if (h2_ != nullptr) nghttp2_session_del(h2_);
    tls_.shutdown();
    if (accepted_socket_ != kInvalidSocket) close_socket(accepted_socket_);
}

bool ServerConnection::start() {
    std::string error;
    if (!set_socket_nonblocking(accepted_socket_, true, error)) {
        PROXY_LOG(Error, "[server] set accepted socket nonblocking failed: " << error);
        return false;
    }
    if (!tls_.begin_accept_server(accepted_socket_, config_.cert_file, config_.key_file)) {
        PROXY_LOG(Error, "[server] begin TLS accept failed: " << tls_.last_error());
        return false;
    }
    accepted_socket_ = kInvalidSocket;
    mode_ = Mode::Handshaking;
    return true;
}

bool ServerConnection::closed() const { return mode_ == Mode::Closed; }
socket_t ServerConnection::client_socket() const { return tls_.raw_socket(); }

void ServerConnection::collect_watches(std::map<socket_t, EventFlags>& desired,
                                       std::map<socket_t, SocketBinding>& bindings) {
    if (closed()) return;
    prepare_http2_output();
    EventFlags client_events = EventFlags::None;
    if (client_wants_read()) client_events = client_events | EventFlags::Readable;
    if (client_wants_write()) client_events = client_events | EventFlags::Writable;
    desired[client_socket()] = client_events;
    bindings[client_socket()] = SocketBinding{SocketBinding::Kind::Client, this, 0};
    for (const auto& kv : streams_) {
        desired[kv.second.sock] = upstream_interest(kv.second);
        bindings[kv.second.sock] = SocketBinding{SocketBinding::Kind::Upstream, this, kv.first};
    }
}

void ServerConnection::on_client_event(bool readable, bool writable, bool error, bool hangup) {
    if (closed()) return;
    if ((error || hangup) && !readable && !writable) { close_connection(); return; }
    if (mode_ == Mode::Handshaking) drive_tls_handshake();
    if (closed()) return;
    if (writable || tls_need_write_ || has_pending_tls_output()) flush_tls_output();
    if (closed()) return;
    if (mode_ == Mode::Http1 && readable) {
        read_http1_request();
        if (!closed()) flush_tls_output();
        return;
    }
    if (mode_ == Mode::Http2 && readable) read_http2_frames();
    if (closed()) return;
    if (mode_ == Mode::Http2) { prepare_http2_output(); flush_tls_output(); }
    if ((hangup || error) && !has_pending_tls_output()) close_connection();
}

void ServerConnection::on_upstream_event(std::uint32_t stream_id, bool readable, bool writable, bool error,
                                         bool hangup) {
    const auto it = streams_.find(stream_id);
    if (it == streams_.end() || closed()) return;
    auto& stream = it->second;
    if ((error || hangup) && !readable && !writable) { close_logical_stream(stream_id, true); return; }
    if (stream.state == UpstreamState::Connecting && (readable || writable || error || hangup)) {
        if (!finish_nonblocking_connect(stream)) { close_logical_stream(stream_id, true); return; }
    }
    if (writable && !process_upstream_write(stream)) { close_logical_stream(stream_id, true); return; }
    if (readable && !process_upstream_read(stream)) close_logical_stream(stream_id, true);
}

bool ServerConnection::client_wants_read() const {
    if (closed()) return false;
    if (tls_need_read_) return true;
    if (mode_ == Mode::Handshaking) return !tls_need_write_;
    if (mode_ == Mode::Http1) return !http1_response_started_;
    return mode_ == Mode::Http2;
}

bool ServerConnection::client_wants_write() const { return !closed() && (tls_need_write_ || has_pending_tls_output()); }
bool ServerConnection::has_pending_tls_output() const { return tls_out_offset_ < tls_out_.size(); }

EventFlags ServerConnection::upstream_interest(const UpstreamStream& stream) const {
    if (stream.state == UpstreamState::Connecting) return EventFlags::Readable | EventFlags::Writable;
    if (stream.state == UpstreamState::ProxyMethodWrite || stream.state == UpstreamState::ProxyConnectWrite) {
        return EventFlags::Writable;
    }
    if (stream.state != UpstreamState::Open) return EventFlags::Readable;
    EventFlags flags = EventFlags::Readable;
    if (stream.pending_uplink_offset < stream.pending_uplink.size()) flags = flags | EventFlags::Writable;
    return flags;
}

void ServerConnection::note_tls_status(proxy::TlsSocket::IoStatus status) {
    tls_need_read_ = (status == proxy::TlsSocket::IoStatus::WantRead);
    tls_need_write_ = (status == proxy::TlsSocket::IoStatus::WantWrite);
}

void ServerConnection::drive_tls_handshake() {
    while (mode_ == Mode::Handshaking) {
        const auto status = tls_.continue_accept_server();
        note_tls_status(status);
        if (status == proxy::TlsSocket::IoStatus::Ok) {
            if (tls_.negotiated_alpn() == "h2") {
                if (!initialize_http2()) { close_connection(); return; }
                mode_ = Mode::Http2;
                prepare_http2_output();
            } else {
                mode_ = Mode::Http1;
            }
            return;
        }
        if (status == proxy::TlsSocket::IoStatus::WantRead || status == proxy::TlsSocket::IoStatus::WantWrite) return;
        PROXY_LOG(Error, "[server] TLS handshake failed");
        close_connection();
        return;
    }
}

bool ServerConnection::initialize_http2() {
    nghttp2_session_callbacks* callbacks = nullptr;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &ServerConnection::on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, &ServerConnection::on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &ServerConnection::on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &ServerConnection::on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &ServerConnection::on_stream_close);
    nghttp2_session_callbacks_set_select_padding_callback2(callbacks, &ServerConnection::select_padding);
    if (nghttp2_session_server_new(&h2_, callbacks, this) != 0) {
        nghttp2_session_callbacks_del(callbacks);
        return false;
    }
    nghttp2_session_callbacks_del(callbacks);
    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, static_cast<uint32_t>(kHttp2WindowSize)},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, kHttp2MaxFrameSize},
    };
    if (nghttp2_submit_settings(h2_, NGHTTP2_FLAG_NONE, settings, 2) != 0 ||
        nghttp2_session_set_local_window_size(h2_, NGHTTP2_FLAG_NONE, 0, kHttp2WindowSize) != 0) return false;
    return queue_session_output();
}

bool ServerConnection::queue_session_output(std::size_t budget_bytes) {
    if (h2_ == nullptr) return true;
    std::size_t sent = 0;
    while (sent < budget_bytes) {
        const uint8_t* data = nullptr;
        const auto len = nghttp2_session_mem_send2(h2_, &data);
        if (len < 0) return false;
        if (len == 0) return true;
        tls_out_.insert(tls_out_.end(), data, data + len);
        sent += static_cast<std::size_t>(len);
    }
    return true;
}

void ServerConnection::prepare_http2_output() {
    if (mode_ != Mode::Http2 || h2_ == nullptr || event_stream_id_ < 0) return;
    if (!downlink_control_.empty() || has_pending_downlink_data()) {
        nghttp2_session_resume_data(h2_, event_stream_id_);
        if (!queue_session_output(kSessionFlushBudgetBytes)) close_connection();
    }
}

void ServerConnection::flush_tls_output() {
    std::size_t flushed = 0;
    while (has_pending_tls_output() && flushed < kTlsWriteBudgetBytes) {
        std::size_t wrote = 0;
        const auto status =
            tls_.write_nonblocking(tls_out_.data() + tls_out_offset_, tls_out_.size() - tls_out_offset_, wrote);
        note_tls_status(status);
        if (status == proxy::TlsSocket::IoStatus::Ok) {
            tls_out_offset_ += wrote;
            flushed += wrote;
            continue;
        }
        if (status == proxy::TlsSocket::IoStatus::WantRead ||
            status == proxy::TlsSocket::IoStatus::WantWrite) return;
        PROXY_LOG(Debug, "[server] closing connection while flushing TLS output");
        close_connection();
        return;
    }
    if (!has_pending_tls_output()) {
        tls_out_.clear();
        tls_out_offset_ = 0;
    }
    if (shutdown_requested_) close_connection();
}

void ServerConnection::read_http1_request() {
    std::array<std::uint8_t, 4096> buf{};
    std::size_t consumed = 0;
    while (!http1_response_started_ && consumed < kHttp1ReadBudgetBytes) {
        std::size_t nread = 0;
        const auto status = tls_.read_nonblocking(buf.data(), buf.size(), nread);
        note_tls_status(status);
        if (status == proxy::TlsSocket::IoStatus::Ok) {
            http1_in_.append(reinterpret_cast<const char*>(buf.data()), nread);
            consumed += nread;
            if (http1_in_.size() > 1024 * 1024) { close_connection(); return; }
            if (http1_in_.find("\r\n\r\n") == std::string::npos) continue;
            Http1Request request;
            if (!parse_http1_request(http1_in_, request)) { close_connection(); return; }
            if (request.method == "GET" && request.path == "/") {
                tls_out_ = build_http1_response(200, "text/html; charset=utf-8", to_bytes(homepage_html()), true);
            } else {
                tls_out_ = build_http1_response(404, "text/plain", to_bytes("not found"));
            }
            tls_out_offset_ = 0;
            http1_response_started_ = true;
            shutdown_requested_ = true;
            return;
        }
        if (status == proxy::TlsSocket::IoStatus::WantRead ||
            status == proxy::TlsSocket::IoStatus::WantWrite) return;
        PROXY_LOG(Debug, "[server] closing connection while reading http1 request");
        close_connection();
        return;
    }
}

void ServerConnection::read_http2_frames() {
    std::array<std::uint8_t, kTunnelIoChunkSize> buf{};
    std::size_t consumed_total = 0;
    while (consumed_total < kTlsReadBudgetBytes) {
        std::size_t nread = 0;
        const auto status = tls_.read_nonblocking(buf.data(), buf.size(), nread);
        note_tls_status(status);
        if (status == proxy::TlsSocket::IoStatus::Ok) {
            consumed_total += nread;
            const auto consumed = nghttp2_session_mem_recv2(h2_, buf.data(), nread);
            if (consumed < 0 || !queue_session_output()) { close_connection(); return; }
            continue;
        }
        if (status == proxy::TlsSocket::IoStatus::WantRead ||
            status == proxy::TlsSocket::IoStatus::WantWrite) return;
        close_connection();
        return;
    }
}

void ServerConnection::start_upstream_connect(std::uint32_t stream_id, std::uint8_t atyp,
                                              const std::string& requested_host, std::uint16_t requested_port) {
    std::string connect_host = requested_host;
    std::uint16_t connect_port = requested_port;
    bool use_socks5 = false;
    if (config_.has_fixed_target) {
        connect_host = config_.fixed_host;
        connect_port = config_.fixed_port;
        use_socks5 = (config_.target_type == ServerConfig::TargetType::Socks5);
        if (config_.target_type == ServerConfig::TargetType::Direct) {
            connect_host = requested_host;
            connect_port = requested_port;
        }
    }
    UpstreamStream stream;
    stream.id = stream_id;
    stream.requested_atyp = atyp;
    stream.requested_host = requested_host;
    stream.requested_port = requested_port;
    stream.use_socks5 = use_socks5;
    bool connected = false;
    std::string error;
    if (!create_nonblocking_tcp_socket(connect_host, connect_port, stream.sock, connected, error)) {
        enqueue_downlink(FrameType::OpenFail, stream_id, encode_open_fail(error));
        return;
    }
    streams_.emplace(stream_id, std::move(stream));
    if (connected) {
        auto it = streams_.find(stream_id);
        if (it != streams_.end() && !finish_nonblocking_connect(it->second)) close_logical_stream(stream_id, true);
    }
}

bool ServerConnection::finish_nonblocking_connect(UpstreamStream& stream) {
    if (stream.state != UpstreamState::Connecting) return true;
    const int connect_error = socket_pending_error(stream.sock);
    if (connect_error != 0) {
        enqueue_downlink(FrameType::OpenFail, stream.id, encode_open_fail(socket_error_text(connect_error)));
        return false;
    }
    if (!stream.use_socks5) {
        stream.state = UpstreamState::Open;
        enqueue_downlink(FrameType::OpenOk, stream.id, encode_open_ok());
        return true;
    }
    stream.state = UpstreamState::ProxyMethodWrite;
    stream.control_out = {0x05, 0x01, 0x00};
    stream.control_out_offset = 0;
    return process_upstream_write(stream);
}

bool ServerConnection::process_upstream_write(UpstreamStream& stream) {
    if (stream.state == UpstreamState::Connecting) return finish_nonblocking_connect(stream);
    if (stream.state == UpstreamState::ProxyMethodWrite || stream.state == UpstreamState::ProxyConnectWrite) {
        std::size_t control_sent = 0;
        while (stream.control_out_offset < stream.control_out.size() && control_sent < kUpstreamWriteBudgetBytes) {
            const auto* data = stream.control_out.data() + stream.control_out_offset;
            const std::size_t remaining = stream.control_out.size() - stream.control_out_offset;
#ifdef _WIN32
            const int ret = ::send(stream.sock, reinterpret_cast<const char*>(data), static_cast<int>(remaining), 0);
#else
            const int ret = static_cast<int>(::send(stream.sock, data, remaining, 0));
#endif
            if (ret > 0) {
                stream.control_out_offset += static_cast<std::size_t>(ret);
                control_sent += static_cast<std::size_t>(ret);
                continue;
            }
            const int code = proxy::last_socket_error_code();
            if (ret < 0 && is_socket_would_block(code)) return true;
            enqueue_downlink(FrameType::OpenFail, stream.id, encode_open_fail(proxy::socket_error_string()));
            return false;
        }
        if (stream.control_out_offset < stream.control_out.size()) return true;
        stream.control_out.clear();
        stream.control_out_offset = 0;
        if (stream.state == UpstreamState::ProxyMethodWrite) {
            stream.state = UpstreamState::ProxyMethodRead;
            stream.control_in.clear();
            stream.control_expected = 2;
            return true;
        }
        stream.state = UpstreamState::ProxyConnectReadHead;
        stream.control_in.clear();
        stream.control_expected = 4;
        return true;
    }
    if (stream.state != UpstreamState::Open) return true;
    std::size_t sent = 0;
    while (stream.pending_uplink_offset < stream.pending_uplink.size() && sent < kUpstreamWriteBudgetBytes) {
        const auto* data = stream.pending_uplink.data() + stream.pending_uplink_offset;
        const std::size_t remaining = stream.pending_uplink.size() - stream.pending_uplink_offset;
#ifdef _WIN32
        const int ret = ::send(stream.sock, reinterpret_cast<const char*>(data), static_cast<int>(remaining), 0);
#else
        const int ret = static_cast<int>(::send(stream.sock, data, remaining, 0));
#endif
        if (ret > 0) {
            stream.pending_uplink_offset += static_cast<std::size_t>(ret);
            sent += static_cast<std::size_t>(ret);
            continue;
        }
        const int code = proxy::last_socket_error_code();
        if (ret < 0 && is_socket_would_block(code)) return true;
        return false;
    }
    if (stream.pending_uplink_offset >= stream.pending_uplink.size()) {
        stream.pending_uplink.clear();
        stream.pending_uplink_offset = 0;
    }
    return true;
}

bool ServerConnection::process_socks5_read(UpstreamStream& stream) {
    std::array<std::uint8_t, 512> buf{};
    while (stream.control_in.size() < stream.control_expected) {
        const std::size_t want = (std::min)(buf.size(), stream.control_expected - stream.control_in.size());
#ifdef _WIN32
        const int ret = ::recv(stream.sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(want), 0);
#else
        const int ret = static_cast<int>(::recv(stream.sock, buf.data(), want, 0));
#endif
        if (ret < 0 && is_socket_would_block(proxy::last_socket_error_code())) return true;
        if (ret <= 0) {
            enqueue_downlink(FrameType::OpenFail, stream.id, encode_open_fail("socks5 upstream closed"));
            return false;
        }
        stream.control_in.insert(stream.control_in.end(), buf.begin(), buf.begin() + ret);
    }
    if (stream.state == UpstreamState::ProxyMethodRead) {
        if (stream.control_in.size() < 2 || stream.control_in[0] != 0x05 || stream.control_in[1] != 0x00) {
            enqueue_downlink(FrameType::OpenFail, stream.id, encode_open_fail("socks5 method rejected"));
            return false;
        }
        stream.control_out = encode_socks5_connect_request(stream.requested_atyp, stream.requested_host, stream.requested_port);
        if (stream.control_out.empty()) {
            enqueue_downlink(FrameType::OpenFail, stream.id, encode_open_fail("bad socks5 target"));
            return false;
        }
        stream.control_out_offset = 0;
        stream.control_in.clear();
        stream.control_expected = 0;
        stream.state = UpstreamState::ProxyConnectWrite;
        return process_upstream_write(stream);
    }
    if (stream.state == UpstreamState::ProxyConnectReadHead) {
        if (stream.control_in.size() < 4 || stream.control_in[0] != 0x05 || stream.control_in[1] != 0x00) {
            enqueue_downlink(FrameType::OpenFail, stream.id, encode_open_fail("socks5 connect rejected"));
            return false;
        }
        const std::uint8_t atyp = stream.control_in[3];
        stream.control_in.clear();
        if (atyp == 0x01) { stream.control_expected = 6; stream.state = UpstreamState::ProxyConnectReadBody; return true; }
        if (atyp == 0x04) { stream.control_expected = 18; stream.state = UpstreamState::ProxyConnectReadBody; return true; }
        if (atyp == 0x03) { stream.control_expected = 1; stream.state = UpstreamState::ProxyConnectReadDomainLength; return true; }
        enqueue_downlink(FrameType::OpenFail, stream.id, encode_open_fail("bad socks5 atyp"));
        return false;
    }
    if (stream.state == UpstreamState::ProxyConnectReadDomainLength) {
        const std::size_t domain_len = stream.control_in.empty() ? 0 : stream.control_in[0];
        stream.control_in.clear();
        stream.control_expected = domain_len + 2;
        stream.state = UpstreamState::ProxyConnectReadBody;
        return true;
    }
    if (stream.state == UpstreamState::ProxyConnectReadBody) {
        stream.control_in.clear();
        stream.control_expected = 0;
        stream.state = UpstreamState::Open;
        enqueue_downlink(FrameType::OpenOk, stream.id, encode_open_ok());
    }
    return true;
}

bool ServerConnection::process_upstream_read(UpstreamStream& stream) {
    if (stream.state == UpstreamState::Connecting) return finish_nonblocking_connect(stream);
    if (stream.state != UpstreamState::Open) return process_socks5_read(stream);
    std::array<std::uint8_t, kTunnelIoChunkSize> buf{};
#ifdef _WIN32
    const int ret = ::recv(stream.sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
#else
    const int ret = static_cast<int>(::recv(stream.sock, buf.data(), buf.size(), 0));
#endif
    if (ret < 0 && is_socket_would_block(proxy::last_socket_error_code())) return true;
    if (ret <= 0) return false;
    enqueue_downlink(FrameType::Data, stream.id, std::vector<std::uint8_t>(buf.begin(), buf.begin() + ret));
    return true;
}

bool ServerConnection::has_pending_downlink_data() const { return !downlink_data_round_robin_.empty(); }

ServerConnection::DownlinkFrame* ServerConnection::current_downlink_data_frame() {
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

void ServerConnection::enqueue_downlink(FrameType type, std::uint32_t stream_id,
                                        const std::vector<std::uint8_t>& payload) {
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
    prepare_http2_output();
}

void ServerConnection::purge_downlink_data_for_stream(std::uint32_t stream_id) {
    downlink_data_by_stream_.erase(stream_id);
    for (auto it = downlink_data_round_robin_.begin(); it != downlink_data_round_robin_.end();) {
        if (*it == stream_id) it = downlink_data_round_robin_.erase(it);
        else ++it;
    }
}

void ServerConnection::close_logical_stream(std::uint32_t stream_id, bool notify_client) {
    const auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        if (notify_client) enqueue_downlink(FrameType::Close, stream_id, {});
        return;
    }
    close_socket(it->second.sock);
    streams_.erase(it);
    purge_downlink_data_for_stream(stream_id);
    if (notify_client) enqueue_downlink(FrameType::Close, stream_id, {});
}

void ServerConnection::close_all_upstreams() {
    for (auto& kv : streams_) close_socket(kv.second.sock);
    streams_.clear();
    downlink_data_by_stream_.clear();
    downlink_data_round_robin_.clear();
}

void ServerConnection::close_connection() {
    if (mode_ != Mode::Closed) {
        PROXY_LOG(Info, "[server] closing connection"
                              << " event_stream=" << event_stream_id_
                              << " shutdown_requested=" << (shutdown_requested_ ? "yes" : "no"));
    }
    close_all_upstreams();
    mode_ = Mode::Closed;
}

std::string ServerConnection::get_header_value_ci(const RequestState& request, const std::string& name) const {
    for (const auto& kv : request.headers) {
        if (ascii_casecmp(kv.first.c_str(), name.c_str()) == 0) return kv.second;
    }
    return {};
}

bool ServerConnection::is_authorized(const RequestState& request) const {
    if (config_.auth_password.empty()) return true;
    if (request.path.rfind("/api/tunnel/", 0) != 0) return true;
    return get_header_value_ci(request, "x-tunnel-auth") == config_.auth_password;
}

void ServerConnection::submit_static_response(int32_t stream_id, int status, const std::string& content_type,
                                              const std::vector<std::uint8_t>& body) {
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
        provider.read_callback = &ServerConnection::read_response_body;
        provider_ptr = &provider;
    }
    nghttp2_submit_response2(h2_, stream_id, headers.data(), headers.size(), provider_ptr);
    queue_session_output();
}

void ServerConnection::handle_request(int32_t stream_id) {
    auto it = requests_.find(stream_id);
    if (it == requests_.end()) return;
    auto& request = it->second;
    if (!is_authorized(request)) { submit_static_response(stream_id, 403, "text/plain", to_bytes("forbidden")); return; }
    if (request.method == "GET" && request.path == "/") {
        submit_static_response(stream_id, 200, "text/html; charset=utf-8", to_bytes(homepage_html()));
        return;
    }
    if (request.method == "POST" && request.path == "/api/tunnel/open") {
        if (tunnel_opened_) { submit_static_response(stream_id, 409, "text/plain", to_bytes("tunnel already opened")); return; }
        tunnel_opened_ = true;
        submit_static_response(stream_id, 200, "text/plain", to_bytes("ok"));
        return;
    }
    if (request.method == "GET" && request.path == "/api/tunnel/events") {
        if (!tunnel_opened_) { submit_static_response(stream_id, 409, "text/plain", to_bytes("open stream required first")); return; }
        if (event_stream_id_ >= 0) { submit_static_response(stream_id, 409, "text/plain", to_bytes("event stream already exists")); return; }
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
        for (const auto& field : header_fields) headers.push_back(make_nv(field.name, field.value));
        nghttp2_data_provider2 provider{};
        provider.source.ptr = &request;
        provider.read_callback = &ServerConnection::read_response_body;
        nghttp2_submit_response2(h2_, stream_id, headers.data(), headers.size(), &provider);
        prepare_http2_output();
        return;
    }
    if (request.method == "POST" && request.path == "/api/tunnel/upload") {
        if (request.response_started) return;
        if (!tunnel_opened_) { submit_static_response(stream_id, 409, "text/plain", to_bytes("open stream required first")); return; }
        submit_static_response(stream_id, 200, "text/plain", to_bytes("ok"));
        nghttp2_session_set_local_window_size(h2_, NGHTTP2_FLAG_NONE, stream_id, kHttp2WindowSize);
        handle_upload_frames(request);
        return;
    }
    if (request.method == "POST" && request.path == "/api/tunnel/close") {
        submit_static_response(stream_id, 200, "text/plain", to_bytes("closed"));
        shutdown_requested_ = true;
        if (event_stream_id_ >= 0) nghttp2_session_resume_data(h2_, event_stream_id_);
        close_all_upstreams();
        queue_session_output();
        return;
    }
    submit_static_response(stream_id, 404, "text/plain", to_bytes("not found"));
}

void ServerConnection::handle_upload_frames(RequestState& request) {
    std::vector<std::pair<FrameHeader, std::vector<std::uint8_t>>> frames;
    if (!proxy::consume_frames(request.body, frames)) { request.body.clear(); return; }
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
            if (streams_.find(tunnel_stream_id) != streams_.end()) {
                enqueue_downlink(FrameType::OpenFail, tunnel_stream_id, encode_open_fail("stream already exists"));
                continue;
            }
            PROXY_LOG(Debug, "[server] open route " << describe_upstream_route(config_, requested_host, requested_port));
            start_upstream_connect(tunnel_stream_id, atyp, requested_host, requested_port);
        } else if (type == FrameType::Data) {
            const auto stream_it = streams_.find(tunnel_stream_id);
            if (stream_it == streams_.end() || stream_it->second.state != UpstreamState::Open) continue;
            auto& stream = stream_it->second;
            stream.pending_uplink.insert(stream.pending_uplink.end(), item.second.begin(), item.second.end());
            if (!process_upstream_write(stream)) close_logical_stream(tunnel_stream_id, true);
        } else if (type == FrameType::Close) {
            close_logical_stream(tunnel_stream_id, false);
        } else if (type == FrameType::Ping) {
            enqueue_downlink(FrameType::Pong, 0, item.second);
        }
    }
}

nghttp2_ssize ServerConnection::read_response_body(nghttp2_session*, int32_t, uint8_t* buf, size_t length,
                                                   uint32_t* data_flags, nghttp2_data_source* source, void* user_data) {
    auto* self = static_cast<ServerConnection*>(user_data);
    auto* request = static_cast<RequestState*>(source->ptr);
    if (request->response_mode == RequestState::ResponseMode::EventStream) {
        DownlinkFrame* active_frame = nullptr;
        if (!self->downlink_control_.empty()) active_frame = &self->downlink_control_.front();
        else active_frame = self->current_downlink_data_frame();
        if (active_frame == nullptr) {
            if (self->shutdown_requested_) { *data_flags |= NGHTTP2_DATA_FLAG_EOF; return 0; }
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
    if (request->response_offset >= request->response_body.size()) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(copy_len);
}

int ServerConnection::on_begin_headers(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<ServerConnection*>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        self->requests_[frame->hd.stream_id] = RequestState{};
    }
    return 0;
}

int ServerConnection::on_header(nghttp2_session*, const nghttp2_frame* frame, const uint8_t* name, size_t namelen,
                                const uint8_t* value, size_t valuelen, uint8_t, void* user_data) {
    auto* self = static_cast<ServerConnection*>(user_data);
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

int ServerConnection::on_data_chunk_recv(nghttp2_session*, uint8_t, int32_t stream_id, const uint8_t* data, size_t len,
                                         void* user_data) {
    auto* self = static_cast<ServerConnection*>(user_data);
    auto it = self->requests_.find(stream_id);
    if (it == self->requests_.end()) return 0;
    it->second.body.insert(it->second.body.end(), data, data + len);
    if (it->second.method == "POST" && it->second.path == "/api/tunnel/upload") self->handle_upload_frames(it->second);
    return 0;
}

int ServerConnection::on_frame_recv(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<ServerConnection*>(user_data);
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        const auto it = self->requests_.find(frame->hd.stream_id);
        if (it != self->requests_.end() && it->second.method == "POST" && it->second.path == "/api/tunnel/upload" &&
            !it->second.response_started) {
            self->handle_request(frame->hd.stream_id);
        }
    }
    if (((frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) ||
         frame->hd.type == NGHTTP2_DATA) &&
        ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0)) {
        self->handle_request(frame->hd.stream_id);
    }
    return 0;
}

int ServerConnection::on_stream_close(nghttp2_session*, int32_t stream_id, uint32_t, void* user_data) {
    auto* self = static_cast<ServerConnection*>(user_data);
    self->requests_.erase(stream_id);
    if (stream_id == self->event_stream_id_) self->event_stream_id_ = -1;
    return 0;
}

nghttp2_ssize ServerConnection::select_padding(nghttp2_session*, const nghttp2_frame* frame, size_t max_payloadlen,
                                               void*) {
    return static_cast<nghttp2_ssize>(
        select_http2_padded_length(frame->hd.type, frame->hd.length, max_payloadlen));
}
