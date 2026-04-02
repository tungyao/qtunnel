#include "server_connection.h"

#include "common/logging.h"
#include "common/tunnel_protocol.h"
#include "homepage_html.h"

#include <array>
#include <sstream>
#include <utility>

namespace {

constexpr std::size_t kTunnelIoChunkSize = 256 * 1024;
constexpr std::size_t kSessionFlushBudgetBytes = 256 * 1024;
constexpr std::size_t kTlsWriteBudgetBytes = 256 * 1024;
constexpr std::size_t kTlsReadBudgetBytes = 256 * 1024;
constexpr std::size_t kHttp1ReadBudgetBytes = 16 * 1024;

using proxy::close_socket;
using proxy::encode_open_fail;
using proxy::EventFlags;
using proxy::FrameType;
using proxy::kInvalidSocket;
using proxy::set_socket_nonblocking;
using proxy::socket_t;
using proxy::to_bytes;

std::string homepage_html() { return generated::kHomepageHtml; }

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
    : accepted_socket_(accepted_socket),
      config_(config),
      h2_driver_(config,
                 Http2SessionDriver::Callbacks{
                     [this](std::uint32_t stream_id, std::uint8_t atyp, const std::string& host,
                            std::uint16_t port) { start_upstream_connect(stream_id, atyp, host, port); },
                     [this](std::uint32_t stream_id, const std::vector<std::uint8_t>& payload) {
                         handle_tunnel_stream_data(stream_id, payload);
                     },
                     [this](std::uint32_t stream_id) { close_logical_stream(stream_id, false); },
                     [this]() { close_all_upstreams(); }}),
      mode_(Mode::Closed) {}

ServerConnection::~ServerConnection() {
    close_all_upstreams();
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
    if (mode_ == Mode::Http2 && !h2_driver_.prepare_output(tls_out_, kSessionFlushBudgetBytes)) {
        close_connection();
        return;
    }
    EventFlags client_events = EventFlags::None;
    if (client_wants_read()) client_events = client_events | EventFlags::Readable;
    if (client_wants_write()) client_events = client_events | EventFlags::Writable;
    desired[client_socket()] = client_events;
    bindings[client_socket()] = SocketBinding{SocketBinding::Kind::Client, this, 0};
    for (const auto& kv : streams_) {
        desired[kv.second.sock] = server_upstream::interest(kv.second);
        bindings[kv.second.sock] = SocketBinding{SocketBinding::Kind::Upstream, this, kv.first};
    }
}

void ServerConnection::on_client_event(bool readable, bool writable, bool error, bool hangup) {
    if (closed()) return;
    if ((error || hangup) && !readable && !writable) {
        close_connection();
        return;
    }
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
    if (mode_ == Mode::Http2) {
        if (!h2_driver_.prepare_output(tls_out_, kSessionFlushBudgetBytes)) {
            close_connection();
            return;
        }
        flush_tls_output();
    }
    if ((hangup || error) && !has_pending_tls_output()) close_connection();
}

void ServerConnection::on_upstream_event(std::uint32_t stream_id, bool readable, bool writable, bool error,
                                         bool hangup) {
    const auto it = streams_.find(stream_id);
    if (it == streams_.end() || closed()) return;
    auto& stream = it->second;
    const auto downlink_sink = [this](FrameType type, std::uint32_t id, const std::vector<std::uint8_t>& payload) {
        enqueue_downlink(type, id, payload);
    };
    if ((error || hangup) && !readable && !writable) {
        close_logical_stream(stream_id, true);
        return;
    }
    if (stream.state == server_upstream::State::Connecting && (readable || writable || error || hangup)) {
        if (!server_upstream::finish_nonblocking_connect(stream, downlink_sink)) {
            close_logical_stream(stream_id, true);
            return;
        }
    }
    if (writable && !server_upstream::process_write(stream, downlink_sink)) {
        close_logical_stream(stream_id, true);
        return;
    }
    if (readable && !server_upstream::process_read(stream, downlink_sink)) close_logical_stream(stream_id, true);
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
                if (!h2_driver_.initialize(tls_out_)) {
                    close_connection();
                    return;
                }
                mode_ = Mode::Http2;
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
    if (mode_ == Mode::Http1 && http1_response_started_ && !has_pending_tls_output()) {
        close_connection();
        return;
    }
    if (mode_ == Mode::Http2 && h2_driver_.shutdown_requested()) close_connection();
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
            if (http1_in_.size() > 1024 * 1024) {
                close_connection();
                return;
            }
            if (http1_in_.find("\r\n\r\n") == std::string::npos) continue;
            Http1Request request;
            if (!parse_http1_request(http1_in_, request)) {
                close_connection();
                return;
            }
            if (request.method == "GET" && request.path == "/") {
                tls_out_ = build_http1_response(200, "text/html; charset=utf-8", to_bytes(homepage_html()), true);
            } else {
                tls_out_ = build_http1_response(404, "text/plain", to_bytes("not found"));
            }
            tls_out_offset_ = 0;
            http1_response_started_ = true;
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
            if (!h2_driver_.receive(buf.data(), nread, tls_out_)) {
                close_connection();
                return;
            }
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
    if (streams_.find(stream_id) != streams_.end()) {
        enqueue_downlink(FrameType::OpenFail, stream_id, encode_open_fail("stream already exists"));
        return;
    }
    PROXY_LOG(Debug, "[server] open route "
                         << server_upstream::describe_route(config_, requested_host, requested_port));
    server_upstream::Peer stream;
    bool connected = false;
    std::string error;
    if (!server_upstream::start_connect(config_, stream_id, atyp, requested_host, requested_port, stream, connected,
                                        error)) {
        enqueue_downlink(FrameType::OpenFail, stream_id, encode_open_fail(error));
        return;
    }
    streams_.emplace(stream_id, std::move(stream));
    if (connected) {
        auto it = streams_.find(stream_id);
        const auto downlink_sink =
            [this](FrameType type, std::uint32_t id, const std::vector<std::uint8_t>& payload) {
                enqueue_downlink(type, id, payload);
            };
        if (it != streams_.end() &&
            !server_upstream::finish_nonblocking_connect(it->second, downlink_sink)) {
            close_logical_stream(stream_id, true);
        }
    }
}

void ServerConnection::enqueue_downlink(FrameType type, std::uint32_t stream_id,
                                        const std::vector<std::uint8_t>& payload) {
    if (mode_ != Mode::Http2) return;
    h2_driver_.enqueue_downlink(type, stream_id, payload, tls_out_, kSessionFlushBudgetBytes);
}

void ServerConnection::handle_tunnel_stream_data(std::uint32_t stream_id, const std::vector<std::uint8_t>& payload) {
    const auto stream_it = streams_.find(stream_id);
    if (stream_it == streams_.end() || stream_it->second.state != server_upstream::State::Open) return;
    auto& stream = stream_it->second;
    stream.pending_uplink.insert(stream.pending_uplink.end(), payload.begin(), payload.end());
    const auto downlink_sink = [this](FrameType type, std::uint32_t id, const std::vector<std::uint8_t>& body) {
        enqueue_downlink(type, id, body);
    };
    if (!server_upstream::process_write(stream, downlink_sink)) close_logical_stream(stream_id, true);
}

void ServerConnection::close_logical_stream(std::uint32_t stream_id, bool notify_client) {
    const auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        if (notify_client) enqueue_downlink(FrameType::Close, stream_id, {});
        return;
    }
    server_upstream::close(it->second);
    streams_.erase(it);
    h2_driver_.purge_downlink_data_for_stream(stream_id);
    if (notify_client) enqueue_downlink(FrameType::Close, stream_id, {});
}

void ServerConnection::close_all_upstreams() {
    for (auto& kv : streams_) server_upstream::close(kv.second);
    streams_.clear();
}

void ServerConnection::close_connection() {
    if (mode_ != Mode::Closed) {
        PROXY_LOG(Info, "[server] closing connection"
                              << " event_stream=" << h2_driver_.event_stream_id()
                              << " shutdown_requested=" << (h2_driver_.shutdown_requested() ? "yes" : "no"));
    }
    close_all_upstreams();
    mode_ = Mode::Closed;
}
