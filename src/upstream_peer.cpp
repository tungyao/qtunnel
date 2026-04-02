#include "upstream_peer.h"

#include "common/socks5.h"

#include <algorithm>
#include <array>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace {

constexpr std::size_t kTunnelIoChunkSize = 256 * 1024;
constexpr std::size_t kUpstreamWriteBudgetBytes = 256 * 1024;

using proxy::close_socket;
using proxy::encode_open_fail;
using proxy::encode_open_ok;
using proxy::EventFlags;
using proxy::FrameType;
using proxy::kInvalidSocket;
using proxy::set_socket_nonblocking;
using proxy::socket_t;

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

} // namespace

namespace server_upstream {

proxy::EventFlags interest(const Peer& peer) {
    if (peer.state == State::Connecting) return EventFlags::Readable | EventFlags::Writable;
    if (peer.state == State::ProxyMethodWrite || peer.state == State::ProxyConnectWrite) {
        return EventFlags::Writable;
    }
    if (peer.state != State::Open) return EventFlags::Readable;
    EventFlags flags = EventFlags::Readable;
    if (peer.pending_uplink_offset < peer.pending_uplink.size()) flags = flags | EventFlags::Writable;
    return flags;
}

bool start_connect(const ServerConfig& config, std::uint32_t stream_id, std::uint8_t requested_atyp,
                   const std::string& requested_host, std::uint16_t requested_port, Peer& peer_out, bool& connected,
                   std::string& error) {
    std::string connect_host = requested_host;
    std::uint16_t connect_port = requested_port;
    bool use_socks5 = false;
    if (config.has_fixed_target) {
        connect_host = config.fixed_host;
        connect_port = config.fixed_port;
        use_socks5 = (config.target_type == ServerConfig::TargetType::Socks5);
        if (config.target_type == ServerConfig::TargetType::Direct) {
            connect_host = requested_host;
            connect_port = requested_port;
        }
    }

    Peer peer;
    peer.id = stream_id;
    peer.requested_atyp = requested_atyp;
    peer.requested_host = requested_host;
    peer.requested_port = requested_port;
    peer.use_socks5 = use_socks5;

    if (!create_nonblocking_tcp_socket(connect_host, connect_port, peer.sock, connected, error)) {
        return false;
    }

    peer_out = std::move(peer);
    return true;
}

bool finish_nonblocking_connect(Peer& peer, const DownlinkSink& downlink_sink) {
    if (peer.state != State::Connecting) return true;
    const int connect_error = socket_pending_error(peer.sock);
    if (connect_error != 0) {
        downlink_sink(FrameType::OpenFail, peer.id, encode_open_fail(socket_error_text(connect_error)));
        return false;
    }
    if (!peer.use_socks5) {
        peer.state = State::Open;
        downlink_sink(FrameType::OpenOk, peer.id, encode_open_ok());
        return true;
    }
    peer.state = State::ProxyMethodWrite;
    peer.control_out = {0x05, 0x01, 0x00};
    peer.control_out_offset = 0;
    return process_write(peer, downlink_sink);
}

bool process_write(Peer& peer, const DownlinkSink& downlink_sink) {
    if (peer.state == State::Connecting) return finish_nonblocking_connect(peer, downlink_sink);
    if (peer.state == State::ProxyMethodWrite || peer.state == State::ProxyConnectWrite) {
        std::size_t control_sent = 0;
        while (peer.control_out_offset < peer.control_out.size() && control_sent < kUpstreamWriteBudgetBytes) {
            const auto* data = peer.control_out.data() + peer.control_out_offset;
            const std::size_t remaining = peer.control_out.size() - peer.control_out_offset;
#ifdef _WIN32
            const int ret = ::send(peer.sock, reinterpret_cast<const char*>(data), static_cast<int>(remaining), 0);
#else
            const int ret = static_cast<int>(::send(peer.sock, data, remaining, 0));
#endif
            if (ret > 0) {
                peer.control_out_offset += static_cast<std::size_t>(ret);
                control_sent += static_cast<std::size_t>(ret);
                continue;
            }
            const int code = proxy::last_socket_error_code();
            if (ret < 0 && is_socket_would_block(code)) return true;
            downlink_sink(FrameType::OpenFail, peer.id, encode_open_fail(proxy::socket_error_string()));
            return false;
        }
        if (peer.control_out_offset < peer.control_out.size()) return true;
        peer.control_out.clear();
        peer.control_out_offset = 0;
        if (peer.state == State::ProxyMethodWrite) {
            peer.state = State::ProxyMethodRead;
            peer.control_in.clear();
            peer.control_expected = 2;
            return true;
        }
        peer.state = State::ProxyConnectReadHead;
        peer.control_in.clear();
        peer.control_expected = 4;
        return true;
    }
    if (peer.state != State::Open) return true;
    std::size_t sent = 0;
    while (peer.pending_uplink_offset < peer.pending_uplink.size() && sent < kUpstreamWriteBudgetBytes) {
        const auto* data = peer.pending_uplink.data() + peer.pending_uplink_offset;
        const std::size_t remaining = peer.pending_uplink.size() - peer.pending_uplink_offset;
#ifdef _WIN32
        const int ret = ::send(peer.sock, reinterpret_cast<const char*>(data), static_cast<int>(remaining), 0);
#else
        const int ret = static_cast<int>(::send(peer.sock, data, remaining, 0));
#endif
        if (ret > 0) {
            peer.pending_uplink_offset += static_cast<std::size_t>(ret);
            sent += static_cast<std::size_t>(ret);
            continue;
        }
        const int code = proxy::last_socket_error_code();
        if (ret < 0 && is_socket_would_block(code)) return true;
        return false;
    }
    if (peer.pending_uplink_offset >= peer.pending_uplink.size()) {
        peer.pending_uplink.clear();
        peer.pending_uplink_offset = 0;
    }
    return true;
}

bool process_read(Peer& peer, const DownlinkSink& downlink_sink) {
    if (peer.state == State::Connecting) return finish_nonblocking_connect(peer, downlink_sink);
    if (peer.state != State::Open) {
        std::array<std::uint8_t, 512> buf{};
        while (peer.control_in.size() < peer.control_expected) {
            const std::size_t want = (std::min)(buf.size(), peer.control_expected - peer.control_in.size());
#ifdef _WIN32
            const int ret = ::recv(peer.sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(want), 0);
#else
            const int ret = static_cast<int>(::recv(peer.sock, buf.data(), want, 0));
#endif
            if (ret < 0 && is_socket_would_block(proxy::last_socket_error_code())) return true;
            if (ret <= 0) {
                downlink_sink(FrameType::OpenFail, peer.id, encode_open_fail("socks5 upstream closed"));
                return false;
            }
            peer.control_in.insert(peer.control_in.end(), buf.begin(), buf.begin() + ret);
        }
        if (peer.state == State::ProxyMethodRead) {
            if (peer.control_in.size() < 2 || peer.control_in[0] != 0x05 || peer.control_in[1] != 0x00) {
                downlink_sink(FrameType::OpenFail, peer.id, encode_open_fail("socks5 method rejected"));
                return false;
            }
            peer.control_out = encode_socks5_connect_request(peer.requested_atyp, peer.requested_host, peer.requested_port);
            if (peer.control_out.empty()) {
                downlink_sink(FrameType::OpenFail, peer.id, encode_open_fail("bad socks5 target"));
                return false;
            }
            peer.control_out_offset = 0;
            peer.control_in.clear();
            peer.control_expected = 0;
            peer.state = State::ProxyConnectWrite;
            return process_write(peer, downlink_sink);
        }
        if (peer.state == State::ProxyConnectReadHead) {
            if (peer.control_in.size() < 4 || peer.control_in[0] != 0x05 || peer.control_in[1] != 0x00) {
                downlink_sink(FrameType::OpenFail, peer.id, encode_open_fail("socks5 connect rejected"));
                return false;
            }
            const std::uint8_t atyp = peer.control_in[3];
            peer.control_in.clear();
            if (atyp == 0x01) {
                peer.control_expected = 6;
                peer.state = State::ProxyConnectReadBody;
                return true;
            }
            if (atyp == 0x04) {
                peer.control_expected = 18;
                peer.state = State::ProxyConnectReadBody;
                return true;
            }
            if (atyp == 0x03) {
                peer.control_expected = 1;
                peer.state = State::ProxyConnectReadDomainLength;
                return true;
            }
            downlink_sink(FrameType::OpenFail, peer.id, encode_open_fail("bad socks5 atyp"));
            return false;
        }
        if (peer.state == State::ProxyConnectReadDomainLength) {
            const std::size_t domain_len = peer.control_in.empty() ? 0 : peer.control_in[0];
            peer.control_in.clear();
            peer.control_expected = domain_len + 2;
            peer.state = State::ProxyConnectReadBody;
            return true;
        }
        if (peer.state == State::ProxyConnectReadBody) {
            peer.control_in.clear();
            peer.control_expected = 0;
            peer.state = State::Open;
            downlink_sink(FrameType::OpenOk, peer.id, encode_open_ok());
        }
        return true;
    }

    std::array<std::uint8_t, kTunnelIoChunkSize> buf{};
#ifdef _WIN32
    const int ret = ::recv(peer.sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
#else
    const int ret = static_cast<int>(::recv(peer.sock, buf.data(), buf.size(), 0));
#endif
    if (ret < 0 && is_socket_would_block(proxy::last_socket_error_code())) return true;
    if (ret <= 0) return false;
    downlink_sink(FrameType::Data, peer.id, std::vector<std::uint8_t>(buf.begin(), buf.begin() + ret));
    return true;
}

void close(Peer& peer) {
    if (peer.sock != kInvalidSocket) {
        close_socket(peer.sock);
        peer.sock = kInvalidSocket;
    }
}

std::string describe_route(const ServerConfig& config, const std::string& requested_host, std::uint16_t requested_port) {
    if (!config.has_fixed_target || config.target_type == ServerConfig::TargetType::Direct) {
        return requested_host + ":" + std::to_string(requested_port) + " (direct)";
    }
    if (config.target_type == ServerConfig::TargetType::Raw) {
        return config.fixed_host + ":" + std::to_string(config.fixed_port) + " (raw fixed)";
    }
    return config.fixed_host + ":" + std::to_string(config.fixed_port) + " (socks5 for " +
           requested_host + ":" + std::to_string(requested_port) + ")";
}

} // namespace server_upstream
