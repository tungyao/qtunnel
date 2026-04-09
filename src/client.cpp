#include "common/logging.h"
#include "common/socks5.h"
#include "common/tls_wrapper.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
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
#endif

namespace {

using proxy::close_socket;
using proxy::kInvalidSocket;
using proxy::parse_log_level;
using proxy::perform_socks5_handshake;
using proxy::send_socks5_reply;
using proxy::send_all_raw;
using proxy::set_log_level;
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
            error = "读取 HTTP 请求头失败";
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
// Bidirectional pipe: copies data between local socket and TLS socket
// ─────────────────────────────────────────────────────────────────────────────
void bidir_pipe(socket_t local_sock, TlsSocket& tls) {
    std::array<uint8_t, 65536> buf;

    while (true) {
        // Wait for either socket to be readable
#ifdef _WIN32
        // Use WSAPoll on Windows
        WSAPOLLFD fds[2];
        fds[0].fd = local_sock;
        fds[0].events = POLLRDNORM;
        fds[1].fd = tls.raw_socket();
        fds[1].events = POLLRDNORM;

        const int poll_ret = WSAPoll(fds, 2, 30000);  // 30 sec timeout
        if (poll_ret < 0) break;
        if (poll_ret == 0) continue;  // timeout

        if (fds[0].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
#else
        // Use poll() on Unix
        pollfd fds[2];
        fds[0].fd = local_sock;
        fds[0].events = POLLIN;
        fds[1].fd = tls.raw_socket();
        fds[1].events = POLLIN;

        const int poll_ret = poll(fds, 2, 30000);  // 30 sec timeout
        if (poll_ret < 0) break;
        if (poll_ret == 0) continue;  // timeout

        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
#endif
            // Local socket is readable
            int n = 0;
#ifdef _WIN32
            n = ::recv(local_sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
#else
            n = static_cast<int>(::recv(local_sock, buf.data(), buf.size(), 0));
#endif
            if (n <= 0) break;  // Connection closed or error

            // Write to TLS
            if (!tls.write_all(buf.data(), static_cast<std::size_t>(n))) break;
        }

#ifdef _WIN32
        if (fds[1].revents & (POLLRDNORM | POLLERR | POLLHUP)) {
#else
        if (fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
#endif
            // TLS socket is readable
            int n = tls.read(buf.data(), buf.size());
            if (n <= 0) break;  // Connection closed or error

            // Write to local socket
            std::string error;
            if (!send_all_raw(local_sock, buf.data(), static_cast<std::size_t>(n), error)) break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-connection handler: runs in its own thread
// ─────────────────────────────────────────────────────────────────────────────
void handle_one_connection(socket_t browser_sock, ClientConfig cfg) {
    // Enable TCP_NODELAY to reduce latency
    int nodelay = 1;
#ifdef _WIN32
    ::setsockopt(browser_sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
#else
    ::setsockopt(browser_sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#endif

    // 1. Accept and handshake with browser (SOCKS5 or HTTP)
    AcceptedProxyRequest accepted;
    std::string handshake_error;
    if (!accept_local_proxy_request(browser_sock, accepted, handshake_error)) {
        PROXY_LOG(Debug, "[conn] 握手失败: " << handshake_error);
        close_socket(browser_sock);
        return;
    }

    // 2. Connect TLS to server
    TlsSocket tls;
    tls.set_ech_config_base64(cfg.ech_config);
    if (!tls.connect_client(cfg.server_host, cfg.server_port, cfg.server_host)) {
        PROXY_LOG(Debug, "[conn] TLS 连接失败: " << tls.last_error());
        close_socket(browser_sock);
        return;
    }

    // 3. Send CONNECT request to server
    std::string connect_request = "CONNECT " + accepted.target.host + ":" +
                                  std::to_string(accepted.target.port) + "\r\n";
    if (!tls.write_all(reinterpret_cast<const uint8_t*>(connect_request.data()),
                        connect_request.size())) {
        PROXY_LOG(Debug, "[conn] 发送 CONNECT 请求失败");
        close_socket(browser_sock);
        tls.shutdown();
        return;
    }

    // 4. Read response from server ("OK\r\n" or "ERR...\r\n")
    std::array<uint8_t, 256> resp_buf;
    int resp_len = tls.read(resp_buf.data(), resp_buf.size());
    if (resp_len <= 0) {
        PROXY_LOG(Debug, "[conn] 读取服务器响应失败");
        close_socket(browser_sock);
        tls.shutdown();
        return;
    }

    std::string response(reinterpret_cast<const char*>(resp_buf.data()), resp_len);
    if (response.find("OK") == std::string::npos && response.find("ok") == std::string::npos) {
        PROXY_LOG(Debug, "[conn] 服务器返回错误: " << response);
        close_socket(browser_sock);
        tls.shutdown();
        return;
    }

    // 5. Send response to browser (protocol-dependent)
    bool send_ok = false;
    if (accepted.protocol == LocalProxyProtocol::Socks5) {
        send_ok = send_socks5_reply(browser_sock, 0x00);
    } else if (accepted.protocol == LocalProxyProtocol::HttpConnect) {
        send_ok = send_http_proxy_response(browser_sock, 200, "Connection Established");
    } else {
        // HttpForward: no reply needed, just send initial payload
        send_ok = true;
    }

    if (!send_ok) {
        PROXY_LOG(Debug, "[conn] 发送浏览器响应失败");
        close_socket(browser_sock);
        tls.shutdown();
        return;
    }

    // 6. Send initial payload if HttpForward
    if (!accepted.initial_payload.empty()) {
        if (!tls.write_all(accepted.initial_payload.data(), accepted.initial_payload.size())) {
            PROXY_LOG(Debug, "[conn] 发送初始请求数据失败");
            close_socket(browser_sock);
            tls.shutdown();
            return;
        }
    }

    // 7. Bidirectional pipe
    PROXY_LOG(Info, "[conn] 隧道建立: " << accepted.target.host << ":" << accepted.target.port);
    bidir_pipe(browser_sock, tls);
    PROXY_LOG(Info, "[conn] 隧道关闭");

    close_socket(browser_sock);
    tls.shutdown();
}

// ─────────────────────────────────────────────────────────────────────────────
// ClientRuntime: simple accept loop
// ─────────────────────────────────────────────────────────────────────────────
class ClientRuntime {
public:
    ClientRuntime(ClientConfig cfg, socket_t listener)
        : cfg_(std::move(cfg)), listener_(listener) {}
    ~ClientRuntime();

    bool start();
    bool should_retry() const { return should_retry_; }
    const std::string& last_error() const { return error_; }
    bool was_connected() const { return connected_; }
    static socket_t make_listener(std::uint16_t port, std::string host);

private:
    void accept_loop();

    ClientConfig cfg_;
    socket_t     listener_ = kInvalidSocket;
    std::atomic<bool> running_{false};
    std::string  error_;
    bool         should_retry_ = false;
    bool         connected_ = false;
};

ClientRuntime::~ClientRuntime() {
    running_ = false;
    if (listener_ != kInvalidSocket) {
        close_socket(listener_);
        listener_ = kInvalidSocket;
    }
}

socket_t ClientRuntime::make_listener(std::uint16_t port, std::string host) {
    // Default to 127.0.0.1 on Windows if host is empty
#ifdef _WIN32
    if (host.empty()) host = "127.0.0.1";
#else
    // On Unix, use IPv6 all addresses (::) for dual-stack support
    if (host.empty()) host = "::";
#endif

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    addrinfo* results = nullptr;
    const std::string port_str = std::to_string(port);
    const int gai_ret = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &results);
    if (gai_ret != 0) {
        std::cerr << "[DEBUG] getaddrinfo failed for " << host << ":" << port_str
                  << " error=" << gai_ret << std::endl;
        return kInvalidSocket;
    }

    socket_t sock = kInvalidSocket;
    for (addrinfo* ai = results; ai; ai = ai->ai_next) {
        sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == kInvalidSocket) {
            std::cerr << "[DEBUG] socket() failed" << std::endl;
            continue;
        }

        int on = 1;
#ifdef _WIN32
        if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&on), sizeof(on)) < 0) {
            std::cerr << "[DEBUG] setsockopt failed" << std::endl;
            close_socket(sock);
            continue;
        }
#else
        if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            std::cerr << "[DEBUG] setsockopt failed" << std::endl;
            close_socket(sock);
            continue;
        }
#endif

        const int bind_ret = ::bind(sock, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        const int listen_ret = (bind_ret == 0) ? ::listen(sock, 128) : -1;

        if (bind_ret == 0 && listen_ret == 0) {
            std::cerr << "[DEBUG] Listener created successfully on " << host << ":" << port_str << std::endl;
            ::freeaddrinfo(results);
            return sock;
        }

        std::cerr << "[DEBUG] bind/listen failed: bind=" << bind_ret << " listen=" << listen_ret << std::endl;
        close_socket(sock);
        sock = kInvalidSocket;
    }
    ::freeaddrinfo(results);
    std::cerr << "[DEBUG] No valid listener socket could be created" << std::endl;
    return kInvalidSocket;
}

bool ClientRuntime::start() {
    if (listener_ == kInvalidSocket) {
        error_ = "本地监听未初始化";
        should_retry_ = true;
        return false;
    }

    PROXY_LOG(Info, "[client] 本地代理监听 " << cfg_.listen_host << ":" << cfg_.listen_port);

    running_ = true;
    connected_ = true;
    should_retry_ = true;

    accept_loop();

    return !error_.empty() ? false : true;
}

void ClientRuntime::accept_loop() {
    while (running_) {
        sockaddr_storage addr{};
        socklen_t addrlen = sizeof(addr);

        const socket_t accepted = ::accept(listener_, reinterpret_cast<sockaddr*>(&addr), &addrlen);
        if (accepted == kInvalidSocket) {
            // Accept failed, might be shutdown
            if (running_) {
                error_ = "accept() failed";
            }
            break;
        }

        // Spawn thread to handle this connection
        std::thread(handle_one_connection, accepted, cfg_).detach();
    }
}

}  // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Main client entry point
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
#endif

    ClientConfig cfg;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--listen") {
            if (i + 1 >= argc) { std::cerr << "--listen 需要端口或 host:port\n"; return 1; }
            const std::string listen_spec = argv[++i];
            if (!parse_host_port(listen_spec, cfg.listen_host, cfg.listen_port)) {
                cfg.listen_host = "127.0.0.1";
                try {
                    cfg.listen_port = static_cast<std::uint16_t>(std::stoi(listen_spec));
                } catch (...) {
                    std::cerr << "无效的监听端口: " << listen_spec << "\n"; return 1;
                }
            }
        } else if (arg == "--log-level") {
            if (i + 1 >= argc) { std::cerr << "--log-level 需要级别\n"; return 1; }
            parse_log_level(argv[++i], cfg.log_level);
        } else if (arg == "--ech-config") {
            if (i + 1 >= argc) { std::cerr << "--ech-config 需要 base64 数据\n"; return 1; }
            cfg.ech_config = argv[++i];
        } else if (cfg.server_host.empty()) {
            if (!parse_host_port(arg, cfg.server_host, cfg.server_port)) {
                cfg.server_host = arg;
            }
        }
    }

    if (cfg.server_host.empty()) {
        std::cerr << "用法: " << argv[0] << " <server:port> [--listen <host:port>] [--log-level <level>]\n";
        return 1;
    }

    set_log_level(cfg.log_level);

    // Set default listen_host if empty
#ifdef _WIN32
    if (cfg.listen_host.empty()) cfg.listen_host = "127.0.0.1";
#else
    if (cfg.listen_host.empty()) cfg.listen_host = "::";
#endif

    // Enable unbuffered output for real-time logging
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    std::cerr << "[DEBUG] Parsed config:" << std::endl
              << "  server: " << cfg.server_host << ":" << cfg.server_port << std::endl
              << "  listen_host: '" << cfg.listen_host << "'" << std::endl
              << "  listen_port: " << cfg.listen_port << std::endl;

    socket_t listener = ClientRuntime::make_listener(cfg.listen_port, cfg.listen_host);
    if (listener == kInvalidSocket) {
        std::cerr << "无法创建监听器: " << cfg.listen_host << ":" << cfg.listen_port << "\n";
        return 1;
    }

    ClientRuntime rt(cfg, listener);
    if (!rt.start()) {
        std::cerr << "客户端启动失败: " << rt.last_error() << "\n";
        return 1;
    }

    return 0;
}
