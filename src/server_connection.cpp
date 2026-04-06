#include "server_connection.h"

#include "common/logging.h"
#include "common/tls_wrapper.h"
#include "homepage_html.h"

#include <array>
#include <sstream>
#include <utility>

namespace {

constexpr std::size_t kTlsReadBudgetBytes   = 256 * 1024;
constexpr std::size_t kHttp1ReadBudgetBytes = 16 * 1024;

using proxy::close_socket;
using proxy::EventFlags;
using proxy::kInvalidSocket;
using proxy::set_socket_nonblocking;
using proxy::socket_t;

std::string homepage_html() { return generated::kHomepageHtml; }

std::vector<uint8_t> build_http1_response(int status,
                                           const std::string& content_type,
                                           const std::string& body,
                                           bool homepage = false) {
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
    std::vector<uint8_t> out(head.begin(), head.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

} // namespace

ServerConnection::ServerConnection(proxy::socket_t accepted_socket,
                                   ServerConfig config,
                                   RuntimeHooks hooks,
                                   std::uint64_t conn_id,
                                   std::string client_addr)
    : accepted_socket_(accepted_socket),
      config_(std::move(config)),
      hooks_(std::move(hooks)),
      h2_driver_(config_,
                 Http2SessionDriver::Callbacks{
                     [this](int32_t stream_id, const std::string& host, uint16_t port) {
                         on_connect_request(stream_id, host, port);
                     },
                     [this](int32_t stream_id, const uint8_t* data, std::size_t len) {
                         on_upload_data(stream_id, data, len);
                     },
                     [this](int32_t stream_id) {
                         on_h2_stream_close(stream_id);
                     }}),
      conn_id_(conn_id),
      client_addr_(std::move(client_addr)),
      mode_(Mode::Closed) {
    h2_driver_.set_send_fn(
        [this](const uint8_t* data, std::size_t len, std::size_t& wrote) {
            return tls_send(data, len, wrote);
        });
    h2_driver_.set_peer_lookup(
        [this](int32_t stream_id) -> server_upstream::Peer* {
            auto it = streams_.find(stream_id);
            return (it != streams_.end()) ? &it->second : nullptr;
        });
}

ServerConnection::~ServerConnection() {
    close_all_upstreams();
    tls_.shutdown();
    if (accepted_socket_ != kInvalidSocket) close_socket(accepted_socket_);
}

bool ServerConnection::start() {
    std::string error;
    if (!set_socket_nonblocking(accepted_socket_, true, error)) {
        PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                      << " set accepted socket nonblocking failed: " << error);
        return false;
    }
    if (!tls_.begin_accept_server(accepted_socket_, config_.cert_file, config_.key_file)) {
        PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                      << " begin TLS accept failed: " << tls_.last_error());
        return false;
    }
    PROXY_LOG(Debug, "[server] conn_id=" << conn_id_
                  << " TLS accept started");
    accepted_socket_ = kInvalidSocket;
    mode_ = Mode::Handshaking;

    proxy::Reactor& reactor = hooks_.get_reactor();
    std::string err;
    if (!reactor.arm(tls_.raw_socket(), EventFlags::Readable, err)) {
        PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                      << " reactor arm client failed: " << err);
        return false;
    }
    return true;
}

void ServerConnection::on_client_event(bool readable, bool writable) {
    if (closed()) return;
    PROXY_LOG(Debug, "[server] conn_id=" << conn_id_
                  << " on_client_event readable=" << readable << " writable=" << writable
                  << " mode=" << static_cast<int>(mode_));
    if (mode_ == Mode::Handshaking) {
        drive_tls_handshake();
        return;
    }
    if (mode_ == Mode::Http1) {
        if (readable) read_http1_request();
        if (!closed()) flush_http1_response();
        return;
    }
    if (mode_ == Mode::Http2) {
        if (writable || tls_need_write_) {
            tls_need_write_ = false;
            drive_session_send();
            if (closed()) return;
        }
        if (readable) {
            read_h2_frames();
            if (closed()) return;
            drive_session_send();
        }
    }
    if (closed()) return;
    EventFlags want = EventFlags::Readable;
    if (tls_need_write_) want = want | EventFlags::Writable;
    proxy::Reactor& reactor = hooks_.get_reactor();
    std::string err;
    reactor.arm(tls_.raw_socket(), want, err);
    PROXY_LOG(Debug, "[server] conn_id=" << conn_id_ << " rearm client for read");
}

void ServerConnection::on_upstream_event(int32_t h2_stream_id, bool readable, bool writable) {
    if (closed()) return;
    auto it = streams_.find(h2_stream_id);
    if (it == streams_.end()) return;
    auto& peer = it->second;

    if (peer.state == server_upstream::State::Connecting && (readable || writable)) {
        bool send_open_ok = false;
        std::string err;
        if (!server_upstream::finish_nonblocking_connect(peer, send_open_ok, err)) {
            PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                          << " stream=" << h2_stream_id << " upstream connect failed: " << err);
            h2_driver_.notify_upstream_failed(h2_stream_id, err);
            close_stream_only(h2_stream_id);
            drive_session_send();
            return;
        }
        if (send_open_ok) {
            PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                          << " stream=" << h2_stream_id << " upstream connected");
            h2_driver_.notify_upstream_connected(h2_stream_id);
            drive_session_send();
            if (closed()) return;
            if (streams_.count(h2_stream_id)) {
                auto& p = streams_.at(h2_stream_id);
                if (p.state == server_upstream::State::Open && !p.pending_uplink.empty()) {
                    const std::size_t offset_before = p.pending_uplink_offset;
                    if (!server_upstream::process_write(p)) {
                        PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                                      << " stream=" << h2_stream_id << " flush pending uplink failed");
                        close_stream_only(h2_stream_id);
                        drive_session_send();
                        return;
                    }
                    const std::size_t wrote = p.pending_uplink_offset - offset_before;
                    if (wrote > 0 && p.pending_uplink.empty()) {
                        p.unconsumed_uplink_bytes -= wrote;
                        h2_driver_.consume_stream_window(h2_stream_id, wrote);
                    }
                }
                rearm_upstream(h2_stream_id, streams_.at(h2_stream_id));
            }
            return;
        }
        if (streams_.count(h2_stream_id)) {
            rearm_upstream(h2_stream_id, streams_.at(h2_stream_id));
        }
        return;
    }

    if (writable && peer.state != server_upstream::State::Open &&
        peer.state != server_upstream::State::Connecting) {
        const server_upstream::State state_before = peer.state;
        PROXY_LOG(Debug, "[server] conn_id=" << conn_id_
                      << " stream=" << h2_stream_id << " SOCKS5 write state=" << static_cast<int>(peer.state));
        if (!server_upstream::process_write(peer)) {
            PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                          << " stream=" << h2_stream_id << " SOCKS5 write failed");
            h2_driver_.notify_upstream_failed(h2_stream_id, "socks5 write failed");
            close_stream_only(h2_stream_id);
            drive_session_send();
            return;
        }
        if (peer.state == server_upstream::State::Open && state_before != server_upstream::State::Open) {
            PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                          << " stream=" << h2_stream_id << " SOCKS5 handshake completed");
            h2_driver_.notify_upstream_connected(h2_stream_id);
            drive_session_send();
            if (closed()) return;
        }
    }

    if (writable && peer.state == server_upstream::State::Open &&
        peer.pending_uplink_offset < peer.pending_uplink.size()) {
        if (!server_upstream::process_write(peer)) {
            PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                          << " stream=" << h2_stream_id << " upstream write error");
            close_stream_only(h2_stream_id);
            return;
        }
        if (peer.unconsumed_uplink_bytes > 0 && peer.pending_uplink.empty()) {
            const std::size_t to_consume = peer.unconsumed_uplink_bytes;
            peer.unconsumed_uplink_bytes = 0;
            h2_driver_.consume_stream_window(h2_stream_id, to_consume);
            drive_session_send();
            if (closed()) return;
        }
    }

    if (readable && !peer.upstream_eof) {
        const server_upstream::State state_before = peer.state;
        if (!server_upstream::process_read(peer)) {
            if (peer.state == server_upstream::State::Open) {
                PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                              << " stream=" << h2_stream_id << " upstream EOF");
                peer.upstream_eof = true;
                h2_driver_.notify_upstream_eof(h2_stream_id);
                drive_session_send();
                if (closed()) return;
            } else {
                PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                              << " stream=" << h2_stream_id << " upstream closed during handshake state=" << static_cast<int>(peer.state));
                h2_driver_.notify_upstream_failed(h2_stream_id, "upstream closed during handshake");
                close_stream_only(h2_stream_id);
                drive_session_send();
                return;
            }
        } else if (state_before != server_upstream::State::Open &&
                   peer.state == server_upstream::State::Open) {
            PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                          << " stream=" << h2_stream_id << " SOCKS5 handshake completed via read");
            h2_driver_.notify_upstream_connected(h2_stream_id);
            drive_session_send();
            if (closed()) return;
            // Flush any buffered uplink data now that upstream is Open
            if (streams_.count(h2_stream_id)) {
                auto& p = streams_.at(h2_stream_id);
                if (!p.pending_uplink.empty()) {
                    const std::size_t offset_before = p.pending_uplink_offset;
                    if (server_upstream::process_write(p)) {
                        const std::size_t wrote = p.pending_uplink_offset - offset_before;
                        if (wrote > 0 && p.pending_uplink.empty()) {
                            p.unconsumed_uplink_bytes -= wrote;
                            h2_driver_.consume_stream_window(h2_stream_id, wrote);
                        }
                    }
                }
            }
        } else if (peer.state == server_upstream::State::Open &&
                   !peer.pending_downlink.empty()) {
            h2_driver_.notify_upstream_data(h2_stream_id);
            drive_session_send();
            if (closed()) return;
        }
    }

    if (!closed() && streams_.count(h2_stream_id)) {
        rearm_upstream(h2_stream_id, streams_.at(h2_stream_id));
    }
}

void ServerConnection::drive_session_send() {
    if (closed() || mode_ != Mode::Http2) return;
    if (!h2_driver_.session_send()) {
        close_connection();
        return;
    }
    if (h2_driver_.shutdown_requested()) {
        close_connection();
        return;
    }
    // Rearm client fd: readable always needed for H2; writable if TLS blocked
    EventFlags want = EventFlags::Readable;
    if (tls_need_write_) want = want | EventFlags::Writable;
    proxy::Reactor& reactor = hooks_.get_reactor();
    std::string err;
    reactor.arm(tls_.raw_socket(), want, err);
}

void ServerConnection::rearm_all_upstreams() {
    for (auto& kv : streams_) {
        rearm_upstream(kv.first, kv.second);
    }
}

void ServerConnection::rearm_upstream(int32_t /*h2_stream_id*/,
                                       const server_upstream::Peer& peer) {
    if (peer.sock == proxy::kInvalidSocket) return;
    const EventFlags flags = server_upstream::interest(peer);
    proxy::Reactor& reactor = hooks_.get_reactor();
    std::string err;
    if (flags == EventFlags::None) {
        reactor.disarm(peer.sock, err);
    } else {
        reactor.arm(peer.sock, flags, err);
    }
}

void ServerConnection::drive_tls_handshake() {
    while (mode_ == Mode::Handshaking) {
        const auto status = tls_.continue_accept_server();
        tls_need_read_  = (status == proxy::TlsSocket::IoStatus::WantRead);
        tls_need_write_ = (status == proxy::TlsSocket::IoStatus::WantWrite);
        if (status == proxy::TlsSocket::IoStatus::Ok) {
            tls_need_read_ = false; tls_need_write_ = false;
            std::string alpn = tls_.negotiated_alpn();
            if (alpn == "h2") {
                PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                              << " ALPN negotiated: h2, initializing h2_driver");
                if (!h2_driver_.initialize()) {
                    PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                                  << " h2_driver initialize failed");
                    close_connection();
                    return;
                }
                mode_ = Mode::Http2;
                PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                              << " h2 mode, checking for pending data");
                read_h2_frames();
                if (closed()) return;
                drive_session_send();
                if (closed()) return;
            } else {
                PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                              << " ALPN=" << alpn << " (falling back to HTTP/1)");
                mode_ = Mode::Http1;
            }
            proxy::Reactor& reactor = hooks_.get_reactor();
            std::string err;
            EventFlags want = EventFlags::Readable;
            if (tls_need_write_) want = want | EventFlags::Writable;
            reactor.arm(tls_.raw_socket(), want, err);
            return;
        }
        if (status == proxy::TlsSocket::IoStatus::WantRead) {
            proxy::Reactor& reactor = hooks_.get_reactor();
            std::string err;
            reactor.arm(tls_.raw_socket(), EventFlags::Readable, err);
            return;
        }
        if (status == proxy::TlsSocket::IoStatus::WantWrite) {
            proxy::Reactor& reactor = hooks_.get_reactor();
            std::string err;
            reactor.arm(tls_.raw_socket(), EventFlags::Writable, err);
            return;
        }
        PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                      << " TLS handshake failed: " << tls_.last_error());
        close_connection();
        return;
    }
}

void ServerConnection::read_http1_request() {
    if (http1_response_started_) return;
    std::array<uint8_t, 4096> buf{};
    std::size_t consumed = 0;
    while (!http1_response_started_ && consumed < kHttp1ReadBudgetBytes) {
        std::size_t nread = 0;
        const auto status = tls_.read_nonblocking(buf.data(), buf.size(), nread);
        tls_need_read_  = (status == proxy::TlsSocket::IoStatus::WantRead);
        tls_need_write_ = (status == proxy::TlsSocket::IoStatus::WantWrite);
        if (status == proxy::TlsSocket::IoStatus::Ok) {
            http1_in_.append(reinterpret_cast<const char*>(buf.data()), nread);
            consumed += nread;
            if (http1_in_.size() > 1024 * 1024) { close_connection(); return; }
            if (http1_in_.find("\r\n\r\n") == std::string::npos) continue;
            std::string method, path;
            const auto line_end = http1_in_.find("\r\n");
            if (line_end != std::string::npos) {
                std::istringstream ls(http1_in_.substr(0, line_end));
                std::string version;
                ls >> method >> path >> version;
            }
            const std::string body = homepage_html();
            if (method == "GET" && path == "/") {
                http1_out_ = build_http1_response(200, "text/html; charset=utf-8", body, true);
            } else {
                http1_out_ = build_http1_response(404, "text/plain", "not found");
            }
            http1_out_offset_ = 0;
            http1_response_started_ = true;
            // Rearm for write
            proxy::Reactor& reactor = hooks_.get_reactor();
            std::string err;
            reactor.arm(tls_.raw_socket(), EventFlags::Writable, err);
            return;
        }
        if (status == proxy::TlsSocket::IoStatus::WantRead ||
            status == proxy::TlsSocket::IoStatus::WantWrite) return;
        close_connection();
        return;
    }
}

void ServerConnection::flush_http1_response() {
    while (http1_out_offset_ < http1_out_.size()) {
        std::size_t wrote = 0;
        const auto status = tls_.write_nonblocking(
            http1_out_.data() + http1_out_offset_,
            http1_out_.size() - http1_out_offset_, wrote);
        tls_need_read_  = (status == proxy::TlsSocket::IoStatus::WantRead);
        tls_need_write_ = (status == proxy::TlsSocket::IoStatus::WantWrite);
        if (status == proxy::TlsSocket::IoStatus::Ok) {
            http1_out_offset_ += wrote;
            continue;
        }
        if (status == proxy::TlsSocket::IoStatus::WantRead ||
            status == proxy::TlsSocket::IoStatus::WantWrite) return;
        close_connection();
        return;
    }
    // Done flushing; close connection
    close_connection();
}

void ServerConnection::read_h2_frames() {
    std::array<uint8_t, 64 * 1024> buf{};
    std::size_t consumed_total = 0;
    while (consumed_total < kTlsReadBudgetBytes) {
        std::size_t nread = 0;
        const auto status = tls_.read_nonblocking(buf.data(), buf.size(), nread);
        tls_need_read_  = (status == proxy::TlsSocket::IoStatus::WantRead);
        tls_need_write_ = (status == proxy::TlsSocket::IoStatus::WantWrite);
        if (status == proxy::TlsSocket::IoStatus::Ok) {
            consumed_total += nread;
            PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                          << " read " << nread << " bytes from client, total=" << consumed_total);
            if (!h2_driver_.receive(buf.data(), nread)) {
                PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                              << " h2_driver.receive failed");
                close_connection();
                return;
            }
            drive_session_send();
            if (closed()) return;
            continue;
        }
        if (status == proxy::TlsSocket::IoStatus::WantRead) {
            PROXY_LOG(Debug, "[server] conn_id=" << conn_id_ << " TLS wants read");
            return;
        }
        if (status == proxy::TlsSocket::IoStatus::WantWrite) {
            PROXY_LOG(Debug, "[server] conn_id=" << conn_id_ << " TLS wants write");
            return;
        }
        PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                      << " TLS read error");
        close_connection();
        return;
    }
}

SendResult ServerConnection::tls_send(const uint8_t* data, std::size_t len,
                                       std::size_t& wrote) {
    wrote = 0;
    std::size_t w = 0;
    const auto status = tls_.write_nonblocking(data, len, w);
    if (status == proxy::TlsSocket::IoStatus::Ok) {
        wrote = w;
        tls_need_write_ = false;
        return SendResult::Ok;
    }
    if (status == proxy::TlsSocket::IoStatus::WantWrite) {
        tls_need_write_ = true;
        // Arm for write so we get notified to retry
        proxy::Reactor& reactor = hooks_.get_reactor();
        std::string err;
        reactor.arm(tls_.raw_socket(),
                    EventFlags::Readable | EventFlags::Writable, err);
        return SendResult::WouldBlock;
    }
    if (status == proxy::TlsSocket::IoStatus::WantRead) {
        tls_need_read_ = true;
        return SendResult::WouldBlock;
    }
    return SendResult::Error;
}

void ServerConnection::on_connect_request(int32_t h2_stream_id,
                                           const std::string& host, uint16_t port) {
    if (streams_.find(h2_stream_id) != streams_.end()) {
        PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                      << " stream=" << h2_stream_id << " CONNECT rejected: stream already exists");
        h2_driver_.notify_upstream_failed(h2_stream_id, "stream already exists");
        return;
    }
    std::string route = server_upstream::describe_route(config_, host, port);
    PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                  << " CONNECT " << route << " stream=" << h2_stream_id);
    server_upstream::Peer peer;
    bool connected = false;
    std::string error;
    auto* dns_resolver = hooks_.get_dns_resolver ? hooks_.get_dns_resolver() : nullptr;
    auto* buffer_pool = hooks_.get_buffer_pool ? hooks_.get_buffer_pool() : nullptr;
    peer.buffer_pool = buffer_pool;  // Set buffer pool for this peer
    if (!server_upstream::start_connect(config_, h2_stream_id, 0x03,
                                         host, port, peer, connected, error, dns_resolver)) {
        PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                      << " stream=" << h2_stream_id << " start_connect failed: " << error);
        h2_driver_.notify_upstream_failed(h2_stream_id, error);
        return;
    }
    PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                  << " stream=" << h2_stream_id << " upstream sock=" << peer.sock
                  << " connected=" << (connected ? "yes" : "no")
                  << " state=" << static_cast<int>(peer.state));
    const proxy::socket_t upstream_sock = peer.sock;
    hooks_.register_upstream(upstream_sock, this, h2_stream_id);
    const EventFlags initial_flags = server_upstream::interest(peer);
    streams_.emplace(h2_stream_id, std::move(peer));
    proxy::Reactor& reactor = hooks_.get_reactor();
    std::string err;
    reactor.arm(upstream_sock, initial_flags, err);

    if (connected) {
        auto& p = streams_.at(h2_stream_id);
        bool send_open_ok = false;
        std::string ferr;
        if (!server_upstream::finish_nonblocking_connect(p, send_open_ok, ferr)) {
            PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                          << " stream=" << h2_stream_id << " finish_nonblocking_connect failed: " << ferr);
            h2_driver_.notify_upstream_failed(h2_stream_id, ferr);
            close_stream_only(h2_stream_id);
            return;
        }
        if (send_open_ok) {
            PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                          << " stream=" << h2_stream_id << " upstream connected immediately");
            h2_driver_.notify_upstream_connected(h2_stream_id);
            auto& p = streams_.at(h2_stream_id);
            if (p.state == server_upstream::State::Open && !p.pending_uplink.empty()) {
                const std::size_t offset_before = p.pending_uplink_offset;
                if (!server_upstream::process_write(p)) {
                    PROXY_LOG(Error, "[server] conn_id=" << conn_id_
                                  << " stream=" << h2_stream_id << " flush pending uplink failed");
                    close_stream_only(h2_stream_id);
                    return;
                }
                const std::size_t wrote = p.pending_uplink_offset - offset_before;
                if (wrote > 0 && p.pending_uplink.empty()) {
                    p.unconsumed_uplink_bytes -= wrote;
                    h2_driver_.consume_stream_window(h2_stream_id, wrote);
                }
            }
        }
    }
}

void ServerConnection::on_upload_data(int32_t h2_stream_id,
                                       const uint8_t* data, std::size_t len) {
    auto it = streams_.find(h2_stream_id);
    if (it == streams_.end()) return;
    auto& peer = it->second;

    // Buffer the uplink data; track unconsumed bytes for window management
    peer.pending_uplink.insert(peer.pending_uplink.end(), data, data + len);
    peer.unconsumed_uplink_bytes += len;

    if (peer.state != server_upstream::State::Open) return;

    // Try to write immediately
    if (!server_upstream::process_write(peer)) {
        close_stream_only(h2_stream_id);
        return;
    }

    // Consume window for bytes that were flushed
    if (peer.unconsumed_uplink_bytes > 0 && peer.pending_uplink.empty()) {
        const std::size_t to_consume = peer.unconsumed_uplink_bytes;
        peer.unconsumed_uplink_bytes = 0;
        h2_driver_.consume_stream_window(h2_stream_id, to_consume);
    }

    // Rearm upstream for writing if there's still pending data
    if (streams_.count(h2_stream_id)) {
        rearm_upstream(h2_stream_id, streams_.at(h2_stream_id));
    }
}

void ServerConnection::on_h2_stream_close(int32_t h2_stream_id) {
    close_stream_only(h2_stream_id);
}

void ServerConnection::close_stream_only(int32_t h2_stream_id) {
    auto it = streams_.find(h2_stream_id);
    if (it == streams_.end()) return;
    const proxy::socket_t sock = it->second.sock;
    server_upstream::close(it->second);
    streams_.erase(it);
    if (sock != proxy::kInvalidSocket) {
        hooks_.unregister_fd(sock);
    }
}

void ServerConnection::close_all_upstreams() {
    // Collect sockets to unregister before clearing (avoid iterator invalidation)
    std::vector<proxy::socket_t> socks;
    for (auto& kv : streams_) {
        socks.push_back(kv.second.sock);
        server_upstream::close(kv.second);
    }
    streams_.clear();
    for (proxy::socket_t s : socks) {
        if (s != proxy::kInvalidSocket) hooks_.unregister_fd(s);
    }
}

void ServerConnection::close_connection() {
    if (mode_ != Mode::Closed) {
        PROXY_LOG(Info, "[server] conn_id=" << conn_id_
                      << " closing connection from=" << client_addr_
                      << " mode=" << static_cast<int>(mode_)
                      << " streams=" << streams_.size()
                      << " shutdown_requested=" << (h2_driver_.shutdown_requested() ? "yes" : "no"));
    }
    close_all_upstreams();
    proxy::Reactor& reactor = hooks_.get_reactor();
    std::string err;
    reactor.disarm(tls_.raw_socket(), err);
    mode_ = Mode::Closed;
}
