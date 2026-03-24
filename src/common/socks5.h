#pragma once

#include <cstdint>
#include <cerrno>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace proxy {

#ifndef PROXY_SOCKET_TYPES_DEFINED
#define PROXY_SOCKET_TYPES_DEFINED
#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif
#endif

struct Socks5Request {
    std::uint8_t atyp = 0;
    std::string host;
    std::uint16_t port = 0;
};

enum class Socks5HandshakeStatus {
    Ok,
    PeerClosed,
    Error
};

inline int recv_exact(socket_t sock, void* buf, std::size_t len) {
    auto* p = static_cast<std::uint8_t*>(buf);
    std::size_t got = 0;
    while (got < len) {
#ifdef _WIN32
        const int ret = ::recv(sock, reinterpret_cast<char*>(p + got), static_cast<int>(len - got), 0);
#else
        const int ret = static_cast<int>(::recv(sock, p + got, len - got, 0));
#endif
        if (ret <= 0) {
            return ret;
        }
        got += static_cast<std::size_t>(ret);
    }
    return static_cast<int>(got);
}

inline int send_exact(socket_t sock, const void* buf, std::size_t len) {
    const auto* p = static_cast<const std::uint8_t*>(buf);
    std::size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        const int ret = ::send(sock, reinterpret_cast<const char*>(p + sent), static_cast<int>(len - sent), 0);
#else
        const int ret = static_cast<int>(::send(sock, p + sent, len - sent, 0));
#endif
        if (ret <= 0) {
            return ret;
        }
        sent += static_cast<std::size_t>(ret);
    }
    return static_cast<int>(sent);
}

inline int last_socket_error_code() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

inline bool is_connection_gone_error(int code) {
#ifdef _WIN32
    return code == WSAECONNRESET || code == WSAECONNABORTED || code == WSAENOTCONN;
#else
    return code == ECONNRESET || code == ECONNABORTED || code == ENOTCONN;
#endif
}

inline Socks5HandshakeStatus classify_recv_failure(const char* stage, int ret, std::string& error) {
    if (ret == 0) {
        error = std::string("客户端在 ") + stage + " 前已断开";
        return Socks5HandshakeStatus::PeerClosed;
    }
    const int code = last_socket_error_code();
    if (is_connection_gone_error(code)) {
        error = std::string("客户端在 ") + stage + " 前已断开";
        return Socks5HandshakeStatus::PeerClosed;
    }
    error = std::string("读取 ") + stage + " 失败";
    return Socks5HandshakeStatus::Error;
}

inline bool send_socks5_reply(socket_t sock, std::uint8_t rep) {
    const std::uint8_t reply[10] = {0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    return send_exact(sock, reply, sizeof(reply)) == static_cast<int>(sizeof(reply));
}

inline Socks5HandshakeStatus perform_socks5_handshake(socket_t sock, Socks5Request& request, std::string& error) {
    std::uint8_t greeting[2] = {};
    int ret = recv_exact(sock, greeting, sizeof(greeting));
    if (ret != static_cast<int>(sizeof(greeting))) {
        return classify_recv_failure("SOCKS5 greeting", ret, error);
    }
    if (greeting[0] != 0x05) {
        error = "仅支持 SOCKS5";
        return Socks5HandshakeStatus::Error;
    }

    std::vector<std::uint8_t> methods(greeting[1], 0);
    if (!methods.empty()) {
        ret = recv_exact(sock, methods.data(), methods.size());
        if (ret != static_cast<int>(methods.size())) {
            return classify_recv_failure("SOCKS5 认证方法", ret, error);
        }
    }
    const std::uint8_t method_select[2] = {0x05, 0x00};
    if (send_exact(sock, method_select, sizeof(method_select)) != static_cast<int>(sizeof(method_select))) {
        error = "发送 method selection 失败";
        return Socks5HandshakeStatus::Error;
    }

    std::uint8_t req_head[4] = {};
    ret = recv_exact(sock, req_head, sizeof(req_head));
    if (ret != static_cast<int>(sizeof(req_head))) {
        return classify_recv_failure("SOCKS5 请求头", ret, error);
    }
    if (req_head[0] != 0x05 || req_head[1] != 0x01) {
        send_socks5_reply(sock, 0x07);
        error = "仅支持 CONNECT";
        return Socks5HandshakeStatus::Error;
    }

    request.atyp = req_head[3];
    if (request.atyp == 0x01) {
        std::uint8_t addr[4] = {};
        ret = recv_exact(sock, addr, sizeof(addr));
        if (ret != static_cast<int>(sizeof(addr))) {
            return classify_recv_failure("IPv4 地址", ret, error);
        }
        char text[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, addr, text, sizeof(text)) == nullptr) {
            error = "IPv4 地址转换失败";
            return Socks5HandshakeStatus::Error;
        }
        request.host = text;
    } else if (request.atyp == 0x04) {
        std::uint8_t addr[16] = {};
        ret = recv_exact(sock, addr, sizeof(addr));
        if (ret != static_cast<int>(sizeof(addr))) {
            return classify_recv_failure("IPv6 地址", ret, error);
        }
        char text[INET6_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET6, addr, text, sizeof(text)) == nullptr) {
            error = "IPv6 地址转换失败";
            return Socks5HandshakeStatus::Error;
        }
        request.host = text;
    } else if (request.atyp == 0x03) {
        std::uint8_t len = 0;
        ret = recv_exact(sock, &len, sizeof(len));
        if (ret != static_cast<int>(sizeof(len))) {
            return classify_recv_failure("域名长度", ret, error);
        }
        std::vector<char> host(len + 1, '\0');
        if (len > 0) {
            ret = recv_exact(sock, host.data(), len);
            if (ret != static_cast<int>(len)) {
                return classify_recv_failure("域名", ret, error);
            }
        }
        request.host.assign(host.data(), len);
    } else {
        send_socks5_reply(sock, 0x08);
        error = "不支持的地址类型";
        return Socks5HandshakeStatus::Error;
    }

    std::uint8_t port_be[2] = {};
    ret = recv_exact(sock, port_be, sizeof(port_be));
    if (ret != static_cast<int>(sizeof(port_be))) {
        return classify_recv_failure("端口", ret, error);
    }
    request.port = static_cast<std::uint16_t>((port_be[0] << 8) | port_be[1]);
    return Socks5HandshakeStatus::Ok;
}

} // namespace proxy
