#include "common/logging.h"
#include "common/tls_wrapper.h"
#include "common/socks5.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using proxy::close_socket;
using proxy::kInvalidSocket;
using proxy::send_all_raw;
using proxy::socket_t;
using proxy::TlsSocket;

// ─────────────────────────────────────────────────────────────────────────────
// Simple bidirectional pipe for tunnel connections
// ─────────────────────────────────────────────────────────────────────────────
void bidir_pipe(TlsSocket& tls, socket_t target_sock) {
    std::array<uint8_t, 65536> buf;

    while (true) {
        // Wait for either socket to be readable
#ifdef _WIN32
        WSAPOLLFD fds[2];
        fds[0].fd = tls.raw_socket();
        fds[0].events = POLLRDNORM;
        fds[1].fd = target_sock;
        fds[1].events = POLLRDNORM;

        const int poll_ret = WSAPoll(fds, 2, 30000);
        if (poll_ret < 0) break;
        if (poll_ret == 0) continue;

        if (fds[0].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
#else
        pollfd fds[2];
        fds[0].fd = tls.raw_socket();
        fds[0].events = POLLIN;
        fds[1].fd = target_sock;
        fds[1].events = POLLIN;

        const int poll_ret = poll(fds, 2, 30000);
        if (poll_ret < 0) break;
        if (poll_ret == 0) continue;

        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
#endif
            // TLS socket is readable
            int n = tls.read(buf.data(), buf.size());
            if (n <= 0) break;

            // Write to target
            std::string error;
            if (!send_all_raw(target_sock, buf.data(), static_cast<std::size_t>(n), error)) break;
        }

#ifdef _WIN32
        if (fds[1].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
#else
        if (fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
#endif
            // Target socket is readable
            int n = 0;
#ifdef _WIN32
            n = ::recv(target_sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
#else
            n = static_cast<int>(::recv(target_sock, buf.data(), buf.size(), 0));
#endif
            if (n <= 0) break;

            // Write to TLS
            if (!tls.write_all(buf.data(), static_cast<std::size_t>(n))) break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parse CONNECT header: "CONNECT host:port\r\n"
// ─────────────────────────────────────────────────────────────────────────────
bool parse_connect_header(const std::string& header, std::string& host, uint16_t& port) {
    // Remove trailing \r\n
    std::string trimmed = header;
    if (trimmed.size() >= 2 && trimmed.substr(trimmed.size()-2) == "\r\n") {
        trimmed = trimmed.substr(0, trimmed.size()-2);
    }

    if (trimmed.size() < 8 || trimmed.substr(0, 8) != "CONNECT ") return false;

    const std::string target_text = trimmed.substr(8);
    const auto colon = target_text.rfind(':');
    if (colon == std::string::npos) return false;

    host = target_text.substr(0, colon);
    try {
        port = static_cast<uint16_t>(std::stoi(target_text.substr(colon + 1)));
    } catch (...) {
        return false;
    }

    return !host.empty() && port != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP connect to target
// ─────────────────────────────────────────────────────────────────────────────
socket_t tcp_connect(const std::string& host, uint16_t port, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* results = nullptr;
    const std::string port_str = std::to_string(port);
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &results) != 0) {
        error = "getaddrinfo failed for " + host;
        return kInvalidSocket;
    }

    socket_t sock = kInvalidSocket;
    for (addrinfo* ai = results; ai; ai = ai->ai_next) {
        sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == kInvalidSocket) continue;

        if (::connect(sock, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            ::freeaddrinfo(results);
            return sock;
        }

        close_socket(sock);
        sock = kInvalidSocket;
    }

    ::freeaddrinfo(results);
    error = "connect failed for " + host + ":" + port_str;
    return kInvalidSocket;
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-connection tunnel handler: runs in its own thread
// ─────────────────────────────────────────────────────────────────────────────
void handle_tunnel_connection(socket_t accepted_sock,
                              const std::string& cert_file,
                              const std::string& key_file) {
    // Enable TCP_NODELAY to reduce latency
    int nodelay = 1;
#ifdef _WIN32
    ::setsockopt(accepted_sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
#else
    ::setsockopt(accepted_sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#endif

    // 1. TLS accept
    TlsSocket tls;
    if (!tls.accept_server(accepted_sock, cert_file, key_file)) {
        PROXY_LOG(Debug, "[tunnel] TLS accept failed: " << tls.last_error());
        return;
    }

    // 2. Read CONNECT header (accumulate until \r\n)
    std::string connect_header;
    std::array<uint8_t, 256> read_buf;

    for (int attempts = 0; attempts < 100; ++attempts) {
        int n = tls.read(read_buf.data(), read_buf.size());
        if (n <= 0) {
            PROXY_LOG(Debug, "[tunnel] Failed to read CONNECT header");
            tls.shutdown();
            return;
        }

        connect_header.append(reinterpret_cast<const char*>(read_buf.data()), n);

        // Check if we have a complete header (ends with \r\n)
        if (connect_header.find("\r\n") != std::string::npos) break;
        if (connect_header.size() > 1024) {  // header too large
            PROXY_LOG(Debug, "[tunnel] CONNECT header too large");
            tls.shutdown();
            return;
        }
    }
    std::string target_host;
    uint16_t target_port = 0;

    if (!parse_connect_header(connect_header, target_host, target_port)) {
        PROXY_LOG(Debug, "[tunnel] Invalid CONNECT header: " << connect_header);
        tls.write_all(reinterpret_cast<const uint8_t*>("ERR invalid header\r\n"), 20);
        tls.shutdown();
        return;
    }

    // 3. TCP connect to target
    std::string conn_error;
    socket_t target_sock = tcp_connect(target_host, target_port, conn_error);
    if (target_sock == kInvalidSocket) {
        PROXY_LOG(Debug, "[tunnel] TCP connect failed: " << conn_error);
        tls.write_all(reinterpret_cast<const uint8_t*>("ERR connect failed\r\n"), 20);
        tls.shutdown();
        return;
    }

    // 4. Send OK response
    const std::string ok_response = "OK\r\n";
    if (!tls.write_all(reinterpret_cast<const uint8_t*>(ok_response.data()), ok_response.size())) {
        PROXY_LOG(Debug, "[tunnel] Failed to send OK response");
        close_socket(target_sock);
        tls.shutdown();
        return;
    }

    // 5. Bidirectional pipe
    PROXY_LOG(Info, "[tunnel] Connected to " << target_host << ":" << target_port);
    bidir_pipe(tls, target_sock);
    PROXY_LOG(Info, "[tunnel] Connection closed");

    close_socket(target_sock);
    tls.shutdown();
}

}  // namespace

// Export the tunnel handler for use in server.cpp (outside anonymous namespace)
void spawn_tunnel_handler(proxy::socket_t accepted_sock,
                         const char* cert_file,
                         const char* key_file) {
    std::string cert_str = cert_file ? cert_file : "";
    std::string key_str = key_file ? key_file : "";
    std::thread(handle_tunnel_connection, accepted_sock, cert_str, key_str).detach();
}
