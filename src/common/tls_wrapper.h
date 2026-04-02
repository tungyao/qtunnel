#pragma once

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <memory>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <array>
#include <vector>

#ifdef _WIN32
#include <mstcpip.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "logging.h"

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

inline void close_socket(socket_t sock) {
    if (sock == kInvalidSocket) {
        return;
    }
#ifdef _WIN32
    ::closesocket(sock);
#else
    ::close(sock);
#endif
}

inline std::string socket_error_string() {
#ifdef _WIN32
    const int code = WSAGetLastError();
    char* message = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD len = FormatMessageA(flags, nullptr, static_cast<DWORD>(code),
                                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                     reinterpret_cast<LPSTR>(&message), 0, nullptr);
    std::string text = "WSA error=" + std::to_string(code);
    if (len != 0 && message != nullptr) {
        text += " ";
        text += message;
        LocalFree(message);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) {
            text.pop_back();
        }
    }
    return text;
#else
    return std::strerror(errno);
#endif
}

inline std::string openssl_error_string(const std::string& prefix) {
    char buf[256] = {};
    const unsigned long code = ERR_get_error();
    ERR_error_string_n(code, buf, sizeof(buf));
    return prefix + ": " + buf;
}

inline std::string ssl_io_error_string(const std::string& prefix, SSL* ssl, int ret) {
    const int ssl_error = SSL_get_error(ssl, ret);
    std::ostringstream oss;
    oss << prefix << ": SSL_get_error=" << ssl_error;

    bool has_queue_error = false;
    for (unsigned long code = ERR_get_error(); code != 0; code = ERR_get_error()) {
        char buf[256] = {};
        ERR_error_string_n(code, buf, sizeof(buf));
        if (!has_queue_error) {
            oss << " errors=[";
            has_queue_error = true;
        } else {
            oss << "; ";
        }
        oss << buf;
    }
    if (has_queue_error) {
        oss << "]";
    }

    switch (ssl_error) {
        case SSL_ERROR_ZERO_RETURN:
            oss << " peer closed the TLS session";
            break;
        case SSL_ERROR_WANT_READ:
            oss << " need more network data";
            break;
        case SSL_ERROR_WANT_WRITE:
            oss << " need socket writable";
            break;
        case SSL_ERROR_SYSCALL:
            if (ret == 0) {
                oss << " peer closed the TCP connection";
            } else {
                oss << " syscall=" << socket_error_string();
            }
            break;
        default:
            if (!has_queue_error && ret == 0) {
                oss << " peer closed the connection unexpectedly";
            }
            break;
    }
    return oss.str();
}

inline bool openssl_global_init() {
    static std::once_flag once;
    std::call_once(once, []() {
#if defined(OPENSSL_IS_BORINGSSL)
        PROXY_LOG(Info, "[server] OPENSSL_IS_BORINGSSL: " << 1);
        OPENSSL_init_ssl(0, nullptr);

#elif defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
#else
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
#endif
    });
    return true;
}

inline bool decode_base64(std::string text, std::vector<std::uint8_t>& out) {
    out.clear();
    std::string normalized;
    normalized.reserve(text.size());
    for (unsigned char ch : text) {
        if (!std::isspace(ch)) {
            normalized.push_back(static_cast<char>(ch));
        }
    }
    if (normalized.empty()) {
        return true;
    }
    if ((normalized.size() % 4) != 0) {
        return false;
    }

    auto decode_char = [](char ch) -> int {
        if (ch >= 'A' && ch <= 'Z') return ch - 'A';
        if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
        if (ch >= '0' && ch <= '9') return ch - '0' + 52;
        if (ch == '+') return 62;
        if (ch == '/') return 63;
        if (ch == '=') return -2;
        return -1;
    };

    out.reserve((normalized.size() / 4) * 3);
    for (std::size_t i = 0; i < normalized.size(); i += 4) {
        const int a = decode_char(normalized[i]);
        const int b = decode_char(normalized[i + 1]);
        const int c = decode_char(normalized[i + 2]);
        const int d = decode_char(normalized[i + 3]);
        if (a < 0 || b < 0 || c == -1 || d == -1) {
            out.clear();
            return false;
        }

        const std::uint32_t block = (static_cast<std::uint32_t>(a) << 18) |
                                    (static_cast<std::uint32_t>(b) << 12) |
                                    (static_cast<std::uint32_t>(c < 0 ? 0 : c) << 6) |
                                    static_cast<std::uint32_t>(d < 0 ? 0 : d);
        out.push_back(static_cast<std::uint8_t>((block >> 16) & 0xffu));
        if (c != -2) {
            out.push_back(static_cast<std::uint8_t>((block >> 8) & 0xffu));
        }
        if (d != -2) {
            out.push_back(static_cast<std::uint8_t>(block & 0xffu));
        }
        if ((c == -2 && d != -2) || (i + 4 != normalized.size() && (c == -2 || d == -2))) {
            out.clear();
            return false;
        }
    }
    return true;
}

inline bool set_socket_nonblocking(socket_t sock, bool enabled, std::string& error) {
#ifdef _WIN32
    u_long mode = enabled ? 1UL : 0UL;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
        error = "ioctlsocket(FIONBIO) 失败: " + socket_error_string();
        return false;
    }
    return true;
#else
    const int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        error = "fcntl(F_GETFL) 失败: " + socket_error_string();
        return false;
    }
    const int next_flags = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    if (fcntl(sock, F_SETFL, next_flags) != 0) {
        error = "fcntl(F_SETFL) 失败: " + socket_error_string();
        return false;
    }
    return true;
#endif
}

struct SocketEvent {
    socket_t sock = kInvalidSocket;
    bool readable = false;
    bool writable = false;
    bool error = false;
    bool hangup = false;
};

class EventDispatcher {
public:
    EventDispatcher()
#ifdef __linux__
        : epoll_fd_(::epoll_create1(EPOLL_CLOEXEC))
#endif
    {}

    ~EventDispatcher() {
#ifdef __linux__
        if (epoll_fd_ >= 0) {
            ::close(epoll_fd_);
            epoll_fd_ = -1;
        }
#endif
    }

    bool valid() const {
#ifdef __linux__
        return epoll_fd_ >= 0;
#else
        return true;
#endif
    }

    bool set(socket_t sock, bool want_read, bool want_write, std::string& error) {
        if (sock == kInvalidSocket) {
            error = "无效 socket";
            return false;
        }
#ifdef __linux__
        epoll_event ev{};
        ev.events = EPOLLERR | EPOLLHUP;
        if (want_read) {
            ev.events |= EPOLLIN | EPOLLRDHUP;
        }
        if (want_write) {
            ev.events |= EPOLLOUT;
        }
        ev.data.fd = sock;
        const auto it = interests_.find(sock);
        const int op = (it == interests_.end()) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        if (::epoll_ctl(epoll_fd_, op, sock, &ev) != 0) {
            error = "epoll_ctl 失败: " + socket_error_string();
            return false;
        }
        interests_[sock] = Interest{want_read, want_write};
        return true;
#else
        pollfds_[sock].fd = sock;
        pollfds_[sock].events = static_cast<short>((want_read ? POLLRDNORM : 0) |
                                                   (want_write ? POLLWRNORM : 0));
        pollfds_[sock].revents = 0;
        return true;
#endif
    }

    bool remove(socket_t sock, std::string& error) {
        (void)error;
        if (sock == kInvalidSocket) {
            return true;
        }
#ifdef __linux__
        interests_.erase(sock);
        if (::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, sock, nullptr) != 0) {
            const int code = errno;
            if (code != ENOENT && code != EBADF) {
                error = "epoll_ctl 删除失败: " + socket_error_string();
                return false;
            }
        }
        return true;
#else
        pollfds_.erase(sock);
        return true;
#endif
    }

    int wait(std::vector<SocketEvent>& events, int timeout_ms, std::string& error) {
        events.clear();
#ifdef __linux__
        std::array<epoll_event, 128> ready{};
        const int ready_count = ::epoll_wait(epoll_fd_, ready.data(), static_cast<int>(ready.size()), timeout_ms);
        if (ready_count < 0) {
            if (errno == EINTR) {
                return 0;
            }
            error = "epoll_wait 失败: " + socket_error_string();
            return -1;
        }
        events.reserve(static_cast<std::size_t>(ready_count));
        for (int i = 0; i < ready_count; ++i) {
            const std::uint32_t mask = ready[static_cast<std::size_t>(i)].events;
            events.push_back(SocketEvent{
                static_cast<socket_t>(ready[static_cast<std::size_t>(i)].data.fd),
                (mask & (EPOLLIN | EPOLLPRI | EPOLLRDHUP)) != 0,
                (mask & EPOLLOUT) != 0,
                (mask & EPOLLERR) != 0,
                (mask & (EPOLLHUP | EPOLLRDHUP)) != 0,
            });
        }
        return ready_count;
#else
        if (pollfds_.empty()) {
            if (timeout_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
            }
            return 0;
        }

        std::vector<WSAPOLLFD> fds;
        fds.reserve(pollfds_.size());
        for (const auto& kv : pollfds_) {
            fds.push_back(kv.second);
        }

        const int ready_count = ::WSAPoll(fds.data(), static_cast<ULONG>(fds.size()), timeout_ms);
        if (ready_count < 0) {
            error = "WSAPoll 失败: " + socket_error_string();
            return -1;
        }

        events.reserve(static_cast<std::size_t>(ready_count));
        for (const auto& fd : fds) {
            if (fd.revents == 0) {
                continue;
            }
            events.push_back(SocketEvent{
                fd.fd,
                (fd.revents & (POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP)) != 0,
                (fd.revents & (POLLWRNORM | POLLOUT)) != 0,
                (fd.revents & POLLERR) != 0,
                (fd.revents & POLLHUP) != 0,
            });
        }
        return ready_count;
#endif
    }

private:
    struct Interest {
        bool want_read = false;
        bool want_write = false;
    };

#ifdef __linux__
    int epoll_fd_ = -1;
    std::map<socket_t, Interest> interests_;
#else
    std::map<socket_t, WSAPOLLFD> pollfds_;
#endif
};

class EventNotifier {
public:
    EventNotifier() = default;
    ~EventNotifier() {
        close();
    }

    bool open(std::string& error) {
        close();
#ifdef _WIN32
        socket_t listener = static_cast<socket_t>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (listener == kInvalidSocket) {
            error = "创建唤醒 listener 失败: " + socket_error_string();
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listener, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
            error = "绑定唤醒 listener 失败: " + socket_error_string();
            close_socket(listener);
            return false;
        }
        if (::listen(listener, 1) != 0) {
            error = "监听唤醒 listener 失败: " + socket_error_string();
            close_socket(listener);
            return false;
        }

        sockaddr_in bound{};
        int bound_len = sizeof(bound);
        if (::getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &bound_len) != 0) {
            error = "获取唤醒 listener 地址失败: " + socket_error_string();
            close_socket(listener);
            return false;
        }

        socket_t writer = static_cast<socket_t>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (writer == kInvalidSocket) {
            error = "创建唤醒 writer 失败: " + socket_error_string();
            close_socket(listener);
            return false;
        }
        if (::connect(writer, reinterpret_cast<const sockaddr*>(&bound), sizeof(bound)) != 0) {
            error = "连接唤醒 writer 失败: " + socket_error_string();
            close_socket(writer);
            close_socket(listener);
            return false;
        }

        socket_t reader = ::accept(listener, nullptr, nullptr);
        if (reader == kInvalidSocket) {
            error = "接受唤醒 reader 失败: " + socket_error_string();
            close_socket(writer);
            close_socket(listener);
            return false;
        }
        close_socket(listener);
        std::string nonblocking_error;
        if (!set_socket_nonblocking(reader, true, nonblocking_error) ||
            !set_socket_nonblocking(writer, true, nonblocking_error)) {
            error = nonblocking_error;
            close_socket(reader);
            close_socket(writer);
            return false;
        }
        reader_ = reader;
        writer_ = writer;
#else
        int fds[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            error = "创建唤醒 socketpair 失败: " + socket_error_string();
            return false;
        }
        reader_ = fds[0];
        writer_ = fds[1];
        std::string nonblocking_error;
        if (!set_socket_nonblocking(reader_, true, nonblocking_error) ||
            !set_socket_nonblocking(writer_, true, nonblocking_error)) {
            error = nonblocking_error;
            close();
            return false;
        }
#endif
        signaled_.store(false);
        return true;
    }

    void close() {
        signaled_.store(false);
        close_socket(reader_);
        close_socket(writer_);
        reader_ = kInvalidSocket;
        writer_ = kInvalidSocket;
    }

    socket_t readable_socket() const {
        return reader_;
    }

    bool signal(std::string& error) {
        if (reader_ == kInvalidSocket || writer_ == kInvalidSocket) {
            error = "唤醒器未初始化";
            return false;
        }

        bool expected = false;
        if (!signaled_.compare_exchange_strong(expected, true)) {
            return true;
        }

        const std::uint8_t byte = 1;
#ifdef _WIN32
        const int ret = ::send(writer_, reinterpret_cast<const char*>(&byte), 1, 0);
#else
        const int ret = static_cast<int>(::send(writer_, &byte, 1, 0));
#endif
        if (ret == 1) {
            return true;
        }

        const int code = last_socket_error_code();
#ifdef _WIN32
        if (code == WSAEWOULDBLOCK) {
#else
        if (code == EAGAIN || code == EWOULDBLOCK) {
#endif
            return true;
        }
        signaled_.store(false);
        error = "发送唤醒信号失败: " + socket_error_string();
        return false;
    }

    void drain() {
        if (reader_ == kInvalidSocket) {
            return;
        }
        std::array<std::uint8_t, 128> buf{};
        while (true) {
#ifdef _WIN32
            const int ret = ::recv(reader_, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
#else
            const int ret = static_cast<int>(::recv(reader_, buf.data(), buf.size(), 0));
#endif
            if (ret > 0) {
                continue;
            }
            break;
        }
        signaled_.store(false);
    }

private:
    socket_t reader_ = kInvalidSocket;
    socket_t writer_ = kInvalidSocket;
    std::atomic<bool> signaled_{false};
};

inline bool wait_socket_writable(socket_t sock, int timeout_ms, std::string& error) {
    EventDispatcher dispatcher;
    if (!dispatcher.valid()) {
        error = "初始化事件分发器失败";
        return false;
    }
    if (!dispatcher.set(sock, false, true, error)) {
        return false;
    }

    std::vector<SocketEvent> events;
    const int ready = dispatcher.wait(events, timeout_ms, error);
    if (ready == 0) {
        error = "连接超时";
        return false;
    }
    if (ready < 0) {
        return false;
    }
    int so_error = 0;
    socklen_t so_len = sizeof(so_error);
    if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &so_len) != 0) {
        error = "getsockopt(SO_ERROR) 失败: " + socket_error_string();
        return false;
    }
    if (so_error != 0) {
#ifdef _WIN32
        error = "连接失败: WSA error=" + std::to_string(so_error);
#else
        error = std::strerror(so_error);
#endif
        return false;
    }
    return true;
}

inline bool is_ip_literal_host(const std::string& host) {
    in_addr ipv4{};
    if (::inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
        return true;
    }
    in6_addr ipv6{};
    return ::inet_pton(AF_INET6, host.c_str(), &ipv6) == 1;
}

inline socket_t connect_tcp(const std::string& host, std::uint16_t port, std::string& error,
                            int timeout_ms = 8000) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    const bool host_is_ip_literal = is_ip_literal_host(host);
    if (!host_is_ip_literal) {
#ifdef AI_ADDRCONFIG
        hints.ai_flags |= AI_ADDRCONFIG;
#endif
    }

    addrinfo* res = nullptr;
    const std::string port_text = std::to_string(port);
    const int gai_ret = ::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &res);
    if (gai_ret != 0) {
#ifdef _WIN32
        error = "getaddrinfo 失败: " + host + ":" + port_text + " code=" + std::to_string(gai_ret);
#else
        error = "getaddrinfo 失败: " + host + ":" + port_text + " " + gai_strerror(gai_ret);
#endif
        return kInvalidSocket;
    }

    socket_t sock = kInvalidSocket;
    std::string last_connect_error;
    std::vector<addrinfo*> candidates;
    for (auto* p = res; p != nullptr; p = p->ai_next) {
        candidates.push_back(p);
    }
    std::stable_sort(candidates.begin(), candidates.end(), [](const addrinfo* lhs, const addrinfo* rhs) {
        const auto rank = [](int family) {
            if (family == AF_INET) {
                return 0;
            }
            if (family == AF_INET6) {
                return 1;
            }
            return 2;
        };
        return rank(lhs->ai_family) < rank(rhs->ai_family);
    });

    const int per_attempt_timeout_ms = host_is_ip_literal ? timeout_ms : std::min(timeout_ms, 2500);
    for (auto* p : candidates) {
        sock = static_cast<socket_t>(::socket(p->ai_family, p->ai_socktype, p->ai_protocol));
        if (sock == kInvalidSocket) {
            continue;
        }

        std::string nonblocking_error;
        if (!set_socket_nonblocking(sock, true, nonblocking_error)) {
            last_connect_error = nonblocking_error;
            close_socket(sock);
            sock = kInvalidSocket;
            continue;
        }

        if (::connect(sock, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) {
            set_socket_nonblocking(sock, false, nonblocking_error);
            break;
        }

#ifdef _WIN32
        const int connect_error = WSAGetLastError();
        const bool pending = connect_error == WSAEWOULDBLOCK || connect_error == WSAEINPROGRESS ||
                             connect_error == WSAEINVAL;
#else
        const int connect_error = errno;
        const bool pending = connect_error == EINPROGRESS;
#endif

        if (pending && wait_socket_writable(sock, per_attempt_timeout_ms, last_connect_error)) {
            set_socket_nonblocking(sock, false, nonblocking_error);
            break;
        }

        if (last_connect_error.empty()) {
            last_connect_error = socket_error_string();
        }
        close_socket(sock);
        sock = kInvalidSocket;
    }
    ::freeaddrinfo(res);

    if (sock == kInvalidSocket) {
        error = "连接失败: " + host + ":" + port_text;
        if (!last_connect_error.empty()) {
            error += " " + last_connect_error;
        }
    }
    return sock;
}

inline bool send_all_raw(socket_t sock, const std::uint8_t* data, std::size_t len, std::string& error) {
    std::size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        const int ret = ::send(sock, reinterpret_cast<const char*>(data + sent), static_cast<int>(len - sent), 0);
#else
        const int ret = static_cast<int>(::send(sock, data + sent, len - sent, 0));
#endif
        if (ret <= 0) {
            error = "socket send 失败: " + socket_error_string();
            return false;
        }
        sent += static_cast<std::size_t>(ret);
    }
    return true;
}

inline std::string hex_fingerprint(const std::uint8_t* data, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        if (i != 0) {
            oss << ':';
        }
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

inline FILE* open_file_read_binary(const std::string& path) {
#ifdef _WIN32
    FILE* fp = nullptr;
    fopen_s(&fp, path.c_str(), "rb");
    return fp;
#else
    return fopen(path.c_str(), "rb");
#endif
}

class TlsSocket {
    
private:
    // 新增成员变量
    bool enable_ech_ = false;
    std::string ech_config_;   // base64 格式的 ECH config list

    // ====================== 完整 Chrome 配置（包含剩余三个需求） ======================
    void configure_chrome_ctx_full(const std::string& server_name) {
        (void)server_name;
        // 基础配置（TLS 版本、Cipher、Groups、SigAlgs、GREASE）
        SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx_.get(), TLS1_3_VERSION);
        SSL_CTX_set_cipher_list(ctx_.get(), chrome_cipher_list());

        // ALPN: h2 优先 + http/1.1
        static const unsigned char kAlpn[] = {0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        SSL_CTX_set_alpn_protos(ctx_.get(), kAlpn, sizeof(kAlpn));

        set_chrome_groups(ctx_.get());
        set_chrome_sigalgs(ctx_.get());
        enable_chrome_features(ctx_.get());   // 包含 GREASE

        // === 1. Extensions 随机 permutation（解决 JA4_r / JA4_ro 差异）===
#if defined(OPENSSL_IS_BORINGSSL)
        SSL_CTX_set_permute_extensions(ctx_.get(), 1);   // 关键！Chrome 的随机打乱
#endif

        // === 2. compress_certificate (brotli) ===
#if defined(OPENSSL_IS_BORINGSSL)
        // 告诉服务器我们支持 Brotli 压缩证书（Chrome 默认行为）
        // 第二个参数是解压回调（我们不需要解压服务器证书，所以传 nullptr）
        SSL_CTX_add_cert_compression_alg(ctx_.get(), TLSEXT_cert_compression_brotli, nullptr, nullptr);
#endif

        // === 3. application_settings (ALPS - Application Layer Protocol Settings) ===
#if defined(OPENSSL_IS_BORINGSSL)
        // Chrome 发送 "h2" 的 SETTINGS（具体值在 HTTP/2 层再精细控制）
        // 这里先在 TLS 层声明支持 h2 的 application settings
        // const unsigned char h2_proto[] = {'h', '2'};
        // SSL_set_alps_use_new_codepoint(ssl_.get(), 1);
        // SSL-level ALPS configuration is applied after SSL_new().
        // 如果需要使用新 codepoint，可调用：SSL_set_alps_use_new_codepoint(ssl_.get(), 1);
#endif

        // === 4. ECH outer（Encrypted Client Hello）===
    }
    bool configure_chrome_ssl() {
#if defined(OPENSSL_IS_BORINGSSL)
        const unsigned char h2_proto[] = {'h', '2'};
        if (SSL_add_application_settings(ssl_.get(), h2_proto, sizeof(h2_proto), nullptr, 0) != 1) {
            last_error_ = openssl_error_string("SSL_add_application_settings failed");
            return false;
        }
        SSL_set_alps_use_new_codepoint(ssl_.get(), 1);
#endif
        return true;
    }
public:
    enum class IoStatus {
        Ok,
        WantRead,
        WantWrite,
        Closed,
        Error
    };

    TlsSocket() = default;
    ~TlsSocket() { shutdown(); }

    TlsSocket(const TlsSocket&) = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;

    bool connect_client(const std::string& host, std::uint16_t port, const std::string& server_name) {
        shutdown();
        if (!openssl_global_init()) {
            last_error_ = "OpenSSL init failed";
            return false;
        }

        bool use_ech = enable_ech_;
        std::vector<std::uint8_t> current_ech_config_list;
        if (use_ech) {
            if (ech_config_.empty()) {
                last_error_ = "ECH is enabled but no config list was provided";
                return false;
            }
            if (!decode_base64(ech_config_, current_ech_config_list) || current_ech_config_list.empty()) {
                last_error_ = "Invalid base64 ECHConfigList";
                return false;
            }
        }

        const int max_attempts = use_ech ? 2 : 1;
        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            socket_t sock = connect_tcp(host, port, last_error_);
            if (sock == kInvalidSocket) {
                return false;
            }

            ctx_.reset(SSL_CTX_new(TLS_client_method()));
            if (!ctx_) {
                last_error_ = "SSL_CTX_new(client) failed";
                close_socket(sock);
                return false;
            }

            configure_chrome_ctx_full(server_name);
            SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_NONE, nullptr);

            ssl_.reset(SSL_new(ctx_.get()));
            if (!ssl_) {
                last_error_ = "SSL_new(client) failed";
                close_socket(sock);
                return false;
            }

            if (!configure_chrome_ssl()) {
                close_socket(sock);
                ssl_.reset();
                return false;
            }
            if (!apply_client_ech_config(current_ech_config_list)) {
                close_socket(sock);
                ssl_.reset();
                return false;
            }

            socket_ = sock;
            SSL_set_fd(ssl_.get(), static_cast<int>(socket_));
            if (!server_name.empty()) {
                SSL_set_tlsext_host_name(ssl_.get(), server_name.c_str());
            }

            ERR_clear_error();
            const int connect_ret = SSL_connect(ssl_.get());
            if (connect_ret == 1) {
                if (!verify_h2_alpn()) {
                    shutdown();
                    return false;
                }

                cache_peer_fingerprint();
                connected_ = true;
                return true;
            }

#if defined(OPENSSL_IS_BORINGSSL)
            if (use_ech && attempt == 0 && should_retry_ech()) {
                cache_ech_rejection_state();
                const std::vector<std::uint8_t> next_ech_config_list = ech_retry_config_list_;
                shutdown();
                current_ech_config_list = next_ech_config_list;
                use_ech = !current_ech_config_list.empty();
                continue;
            }
#endif

            last_error_ = ssl_io_error_string("SSL_connect failed", ssl_.get(), connect_ret);
            shutdown();
            return false;
        }

        last_error_ = "ECH retry was rejected by the server";
        return false;
    }
    // ====================== 客户端 Chrome 146 指纹核心 ======================

    // ====================== 服务端保持不变 ======================
    bool accept_server(socket_t accepted_socket,
                       const std::string& cert_file = std::string(),
                       const std::string& key_file = std::string()) {
        shutdown();
        if (!openssl_global_init()) {
            last_error_ = "OpenSSL init failed";
            close_socket(accepted_socket);
            return false;
        }

        ctx_.reset(SSL_CTX_new(TLS_server_method()));
        if (!ctx_) {
            last_error_ = "SSL_CTX_new(server) failed";
            close_socket(accepted_socket);
            return false;
        }
        configure_common_ctx(true);
        if (!cert_file.empty() || !key_file.empty()) {
            if (cert_file.empty() || key_file.empty()) {
                last_error_ = "cert_file and key_file must be provided together";
                close_socket(accepted_socket);
                return false;
            }
            if (!load_server_credentials(cert_file, key_file)) {
                close_socket(accepted_socket);
                return false;
            }
        } else if (!generate_server_credentials()) {
            close_socket(accepted_socket);
            return false;
        }
        if (SSL_CTX_use_certificate(ctx_.get(), cert_.get()) != 1 ||
            SSL_CTX_use_PrivateKey(ctx_.get(), pkey_.get()) != 1 ||
            SSL_CTX_check_private_key(ctx_.get()) != 1) {
            last_error_ = openssl_error_string("Load server certificate failed");
            close_socket(accepted_socket);
            return false;
        }

        socket_ = accepted_socket;
        ssl_.reset(SSL_new(ctx_.get()));
        if (!ssl_) {
            last_error_ = "SSL_new(server) failed";
            shutdown();
            return false;
        }
        SSL_set_fd(ssl_.get(), static_cast<int>(socket_));
        ERR_clear_error();
        const int accept_ret = SSL_accept(ssl_.get());
        if (accept_ret != 1) {
            last_error_ = ssl_io_error_string("SSL_accept failed", ssl_.get(), accept_ret);
            shutdown();
            return false;
        }
        cache_tls_diagnostics();

        connected_ = true;
        return true;
    }

    bool begin_accept_server(socket_t accepted_socket,
                             const std::string& cert_file = std::string(),
                             const std::string& key_file = std::string()) {
        shutdown();
        if (!openssl_global_init()) {
            last_error_ = "OpenSSL init failed";
            close_socket(accepted_socket);
            return false;
        }

        ctx_.reset(SSL_CTX_new(TLS_server_method()));
        if (!ctx_) {
            last_error_ = "SSL_CTX_new(server) failed";
            close_socket(accepted_socket);
            return false;
        }
        configure_common_ctx(true);
        if (!cert_file.empty() || !key_file.empty()) {
            if (cert_file.empty() || key_file.empty()) {
                last_error_ = "cert_file and key_file must be provided together";
                close_socket(accepted_socket);
                return false;
            }
            if (!load_server_credentials(cert_file, key_file)) {
                close_socket(accepted_socket);
                return false;
            }
        } else if (!generate_server_credentials()) {
            close_socket(accepted_socket);
            return false;
        }
        if (SSL_CTX_use_certificate(ctx_.get(), cert_.get()) != 1 ||
            SSL_CTX_use_PrivateKey(ctx_.get(), pkey_.get()) != 1 ||
            SSL_CTX_check_private_key(ctx_.get()) != 1) {
            last_error_ = openssl_error_string("Load server certificate failed");
            close_socket(accepted_socket);
            return false;
        }

        socket_ = accepted_socket;
        ssl_.reset(SSL_new(ctx_.get()));
        if (!ssl_) {
            last_error_ = "SSL_new(server) failed";
            shutdown();
            return false;
        }
        SSL_set_fd(ssl_.get(), static_cast<int>(socket_));
        return true;
    }

    IoStatus continue_accept_server() {
        if (!ssl_) {
            last_error_ = "SSL state is not initialized";
            return IoStatus::Error;
        }

        ERR_clear_error();
        const int accept_ret = SSL_accept(ssl_.get());
        if (accept_ret == 1) {
            cache_tls_diagnostics();
            connected_ = true;
            return IoStatus::Ok;
        }
        return classify_io_result("SSL_accept failed", accept_ret, true);
    }

    int read(std::uint8_t* data, std::size_t len) {
        if (!connected_ || len == 0) {
            return 0;
        }
        const int ret = SSL_read(ssl_.get(), data, static_cast<int>(len));
        if (ret <= 0) {
            const int err = SSL_get_error(ssl_.get(), ret);
            if (err == SSL_ERROR_ZERO_RETURN) {
                return 0;
            }
            last_error_ = "SSL_read 失败: code=" + std::to_string(err);
            return -1;
        }
        return ret;
    }

    IoStatus read_nonblocking(std::uint8_t* data, std::size_t len, std::size_t& bytes_read) {
        bytes_read = 0;
        if (!connected_ || len == 0) {
            return IoStatus::Closed;
        }

        ERR_clear_error();
        const int ret = SSL_read(ssl_.get(), data, static_cast<int>(len));
        if (ret > 0) {
            bytes_read = static_cast<std::size_t>(ret);
            return IoStatus::Ok;
        }
        return classify_io_result("SSL_read failed", ret, true);
    }

    int write(const std::uint8_t* data, std::size_t len) {
        if (!connected_ || len == 0) {
            return 0;
        }
        const int ret = SSL_write(ssl_.get(), data, static_cast<int>(len));
        if (ret <= 0) {
            const int err = SSL_get_error(ssl_.get(), ret);
            last_error_ = "SSL_write 失败: code=" + std::to_string(err);
            return -1;
        }
        return ret;
    }

    IoStatus write_nonblocking(const std::uint8_t* data, std::size_t len, std::size_t& bytes_written) {
        bytes_written = 0;
        if (!connected_ || len == 0) {
            return IoStatus::Closed;
        }

        ERR_clear_error();
        const int ret = SSL_write(ssl_.get(), data, static_cast<int>(len));
        if (ret > 0) {
            bytes_written = static_cast<std::size_t>(ret);
            return IoStatus::Ok;
        }
        return classify_io_result("SSL_write failed", ret, false);
    }

    bool write_all(const std::uint8_t* data, std::size_t len) {
        std::size_t sent = 0;
        while (sent < len) {
            const int ret = write(data + sent, len - sent);
            if (ret <= 0) {
                return false;
            }
            sent += static_cast<std::size_t>(ret);
        }
        return true;
    }

    void shutdown() {
        connected_ = false;
        ech_accepted_ = false;
        ech_name_override_.clear();
        ech_retry_config_list_.clear();
        ssl_.reset();
        ctx_.reset();
        cert_.reset();
        pkey_.reset();
        if (socket_ != kInvalidSocket) {
            close_socket(socket_);
            socket_ = kInvalidSocket;
        }
    }

    std::string last_error() const { return last_error_; }
    std::string peer_fingerprint() const { return peer_fingerprint_; }
    std::string negotiated_alpn() const { return negotiated_alpn_; }
    std::string negotiated_tls_version() const { return negotiated_tls_version_; }
    std::string negotiated_cipher() const { return negotiated_cipher_; }
    std::string requested_server_name() const { return requested_server_name_; }
    bool ech_accepted() const { return ech_accepted_; }
    std::string ech_name_override() const { return ech_name_override_; }
    bool has_ech_retry_config_list() const { return !ech_retry_config_list_.empty(); }
    socket_t raw_socket() const { return socket_; }
    bool connected() const { return connected_; }

    void set_ech_config_base64(const std::string& ech_config_base64) {
        ech_config_ = ech_config_base64;
        enable_ech_ = !ech_config_.empty();
    }

    void set_enable_ech(bool enabled) {
        enable_ech_ = enabled;
        if (!enable_ech_) {
            ech_config_.clear();
        }
    }

    void set_enable_ech_grease(bool enabled) {
        enable_ech_grease_ = enabled;
    }

private:
    using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
    using SSL_ptr = std::unique_ptr<SSL, decltype(&SSL_free)>;
    using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

    // ====================== Chrome 146 指纹配置函数 ======================
    static const char* chrome_cipher_list() {
        // 精确匹配你提供的 JSON 中的 cipher_suites（含 GREASE 前缀）
        return "GREASE:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
               "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
               "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
               "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
               "TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:"
               "TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA";
    }

    void set_chrome_groups(SSL_CTX* ctx) {
#if defined(OPENSSL_IS_BORINGSSL)
        // 精确匹配 JSON：GREASE + X25519MLKEM768 + x25519 + secp256r1 + secp384r1
        const char* groups = "GREASE:X25519MLKEM768:x25519:secp256r1:secp384r1";
        SSL_CTX_set1_groups_list(ctx, groups);
#endif
    }

    void set_chrome_sigalgs(SSL_CTX* ctx) {
#if defined(OPENSSL_IS_BORINGSSL)
        // 精确匹配 JSON 中的 signature_algorithms
        const char* sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
                              "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
                              "rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
        SSL_CTX_set1_sigalgs_list(ctx, sigalgs);
#endif
    }

    void enable_chrome_features(SSL_CTX* ctx) {
#if defined(OPENSSL_IS_BORINGSSL)
        SSL_CTX_set_grease_enabled(ctx, 1);           // 必须开启 GREASE（Chrome 关键特性）
        // 如果你的 BoringSSL fork 支持 extension permutation，可在这里打开
        SSL_CTX_set_permute_extensions(ctx, 1);    // 可选，部分 fork 才有
#endif
    }

    void configure_chrome_ctx() {
        // TLS 版本
        SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx_.get(), TLS1_3_VERSION);

        // Cipher Suites（含 GREASE）
        SSL_CTX_set_cipher_list(ctx_.get(), chrome_cipher_list());

        // ALPN：h2 优先 + http/1.1（完全匹配 Chrome）
        static const unsigned char kAlpn[] = {
            0x02, 'h', '2',
            0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        SSL_CTX_set_alpn_protos(ctx_.get(), kAlpn, sizeof(kAlpn));

        // Chrome 146 关键扩展配置
        set_chrome_groups(ctx_.get());
        set_chrome_sigalgs(ctx_.get());
        enable_chrome_features(ctx_.get());

        // 其他扩展（ECH、compress_certificate、application_settings 等）
        // 若需要 100% 完美，建议继续 patch BoringSSL 的 ext_key_share / ech 实现
    }

    // ====================== 旧版通用配置（仅服务端保留） ======================
    static int select_alpn_h2(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                              const unsigned char* in, unsigned int inlen, void* /*arg*/) {
        unsigned int offset = 0;
        while (offset < inlen) {
            const unsigned int len = in[offset++];
            if (offset + len > inlen) break;
            if (len == 2 && std::memcmp(in + offset, "h2", 2) == 0) {
                *out = in + offset;
                *outlen = static_cast<unsigned char>(len);
                return SSL_TLSEXT_ERR_OK;
            }
            offset += len;
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    void configure_common_ctx(bool server_mode) {
        static const unsigned char kClientAlpn[] = {2, 'h', '2'};
        SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx_.get(), TLS1_3_VERSION);
#if defined(OPENSSL_IS_BORINGSSL)
        SSL_CTX_set_cipher_list(
            ctx_.get(),
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
#else
        SSL_CTX_set_ciphersuites(
            ctx_.get(),
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
        SSL_CTX_set_cipher_list(
            ctx_.get(),
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
#endif
        if (server_mode) {
            SSL_CTX_set_alpn_select_cb(ctx_.get(), &TlsSocket::select_alpn_h2, nullptr);
        } else {
            SSL_CTX_set_alpn_protos(ctx_.get(), kClientAlpn, sizeof(kClientAlpn));
        }
    }


    bool apply_client_ech_config(const std::vector<std::uint8_t>& ech_config_list) {
#if defined(OPENSSL_IS_BORINGSSL)
        SSL_set_enable_ech_grease(ssl_.get(), enable_ech_grease_ ? 1 : 0);
        if (ech_config_list.empty()) {
            return true;
        }
        if (SSL_set1_ech_config_list(ssl_.get(), ech_config_list.data(), ech_config_list.size()) != 1) {
            last_error_ = openssl_error_string("SSL_set1_ech_config_list failed");
            return false;
        }
        return true;
#else
        (void)ech_config_list;
        if (enable_ech_) {
            last_error_ = "ECH requires BoringSSL";
            return false;
        }
        return true;
#endif
    }

    bool should_retry_ech() const {
#if defined(OPENSSL_IS_BORINGSSL)
        const unsigned long code = ERR_peek_last_error();
        return code != 0 && ERR_GET_REASON(code) == SSL_R_ECH_REJECTED;
#else
        return false;
#endif
    }

    void cache_ech_rejection_state() {
        ech_name_override_.clear();
        ech_retry_config_list_.clear();
#if defined(OPENSSL_IS_BORINGSSL)
        const char* override_name = nullptr;
        size_t override_name_len = 0;
        SSL_get0_ech_name_override(ssl_.get(), &override_name, &override_name_len);
        if (override_name != nullptr && override_name_len > 0) {
            ech_name_override_.assign(override_name, override_name_len);
        }

        const std::uint8_t* retry_configs = nullptr;
        size_t retry_configs_len = 0;
        SSL_get0_ech_retry_configs(ssl_.get(), &retry_configs, &retry_configs_len);
        if (retry_configs != nullptr && retry_configs_len > 0) {
            ech_retry_config_list_.assign(retry_configs, retry_configs + retry_configs_len);
        }
#endif
    }
    // ====================== 其余辅助函数保持不变 ======================
    void cache_negotiated_alpn() {
        negotiated_alpn_.clear();
        const unsigned char* alpn = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(ssl_.get(), &alpn, &alpn_len);
        if (alpn != nullptr && alpn_len > 0) {
            negotiated_alpn_.assign(reinterpret_cast<const char*>(alpn), alpn_len);
        }
    }

    void cache_tls_diagnostics() {
        cache_negotiated_alpn();
        negotiated_tls_version_.clear();
        negotiated_cipher_.clear();
        requested_server_name_.clear();
        ech_accepted_ = false;

        const char* version = SSL_get_version(ssl_.get());
        if (version != nullptr) {
            negotiated_tls_version_ = version;
        }

        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_.get());
        if (cipher != nullptr) {
            const char* cipher_name = SSL_CIPHER_get_name(cipher);
            if (cipher_name != nullptr) {
                negotiated_cipher_ = cipher_name;
            }
        }

        const char* sni = SSL_get_servername(ssl_.get(), TLSEXT_NAMETYPE_host_name);
        if (sni != nullptr) {
            requested_server_name_ = sni;
        }
#if defined(OPENSSL_IS_BORINGSSL)
        ech_accepted_ = SSL_ech_accepted(ssl_.get()) == 1;
#endif
    }

    bool verify_h2_alpn() {
        cache_tls_diagnostics();
        if (negotiated_alpn_ == "h2") {
            return true;
        }
        last_error_ = "ALPN 未协商到 h2";
        return false;
    }

    IoStatus classify_io_result(const std::string& prefix, int ret, bool treat_zero_as_closed) {
        const int err = SSL_get_error(ssl_.get(), ret);
        if (err == SSL_ERROR_WANT_READ) {
            return IoStatus::WantRead;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            return IoStatus::WantWrite;
        }
        if (treat_zero_as_closed && (err == SSL_ERROR_ZERO_RETURN || ret == 0)) {
            return IoStatus::Closed;
        }
        last_error_ = ssl_io_error_string(prefix, ssl_.get(), ret);
        return IoStatus::Error;
    }

    bool load_server_credentials(const std::string& cert_file, const std::string& key_file) {
        if (cert_file.empty() || key_file.empty()) return false;

        FILE* cert_fp = open_file_read_binary(cert_file);
        if (!cert_fp) {
            last_error_ = "打开证书文件失败: " + cert_file;
            return false;
        }
        X509* loaded_cert = PEM_read_X509(cert_fp, nullptr, nullptr, nullptr);
        fclose(cert_fp);
        if (!loaded_cert) {
            last_error_ = openssl_error_string("读取 PEM 证书失败");
            return false;
        }

        FILE* key_fp = open_file_read_binary(key_file);
        if (!key_fp) {
            X509_free(loaded_cert);
            last_error_ = "打开私钥文件失败: " + key_file;
            return false;
        }
        EVP_PKEY* loaded_key = PEM_read_PrivateKey(key_fp, nullptr, nullptr, nullptr);
        fclose(key_fp);
        if (!loaded_key) {
            X509_free(loaded_cert);
            last_error_ = openssl_error_string("读取 PEM 私钥失败");
            return false;
        }

        cert_.reset(loaded_cert);
        pkey_.reset(loaded_key);
        return true;
    }

    bool generate_server_credentials() {
        EVP_PKEY* raw_pkey = nullptr;
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!pctx) {
            last_error_ = openssl_error_string("EVP_PKEY_CTX_new_id 失败");
            return false;
        }

        bool ok = false;
        do {
            if (EVP_PKEY_paramgen_init(pctx) <= 0 ||
                EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0) {
                last_error_ = openssl_error_string("EC 参数生成初始化失败");
                break;
            }

            EVP_PKEY* params = nullptr;
            if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
                last_error_ = openssl_error_string("EVP_PKEY_paramgen 失败");
                break;
            }

            EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, nullptr);
            EVP_PKEY_free(params);
            if (!kctx) {
                last_error_ = openssl_error_string("EVP_PKEY_CTX_new(keygen) 失败");
                break;
            }
            if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &raw_pkey) <= 0) {
                EVP_PKEY_CTX_free(kctx);
                last_error_ = openssl_error_string("EVP_PKEY_keygen 失败");
                break;
            }
            EVP_PKEY_CTX_free(kctx);

            cert_.reset(X509_new());
            if (!cert_) {
                last_error_ = openssl_error_string("X509_new 失败");
                break;
            }
            pkey_.reset(raw_pkey);

            ASN1_INTEGER_set(X509_get_serialNumber(cert_.get()), 1);
            X509_gmtime_adj(X509_get_notBefore(cert_.get()), 0);
            X509_gmtime_adj(X509_get_notAfter(cert_.get()), 60L * 60L * 24L * 365L * 5L);
            X509_set_version(cert_.get(), 2);
            X509_set_pubkey(cert_.get(), pkey_.get());

            X509_NAME* name = X509_get_subject_name(cert_.get());
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>("qtunnel.local"), -1, -1, 0);
            X509_set_issuer_name(cert_.get(), name);

            if (X509_sign(cert_.get(), pkey_.get(), EVP_sha384()) <= 0) {
                last_error_ = openssl_error_string("X509_sign 失败");
                break;
            }
            ok = true;
        } while (false);

        EVP_PKEY_CTX_free(pctx);
        if (!ok && raw_pkey) EVP_PKEY_free(raw_pkey);
        return ok;
    }

    void cache_peer_fingerprint() {
#if defined(OPENSSL_IS_BORINGSSL)
        X509* peer = SSL_get_peer_certificate(ssl_.get());
#else
        X509* peer = SSL_get1_peer_certificate(ssl_.get());
#endif
        if (!peer) return;
        unsigned char md[SHA256_DIGEST_LENGTH] = {};
        unsigned int md_len = 0;
        if (X509_digest(peer, EVP_sha256(), md, &md_len) == 1) {
            peer_fingerprint_ = hex_fingerprint(md, md_len);
        }
        X509_free(peer);
    }

private:
    socket_t socket_ = kInvalidSocket;
    SSL_CTX_ptr ctx_{nullptr, SSL_CTX_free};
    SSL_ptr ssl_{nullptr, SSL_free};
    X509_ptr cert_{nullptr, X509_free};
    EVP_PKEY_ptr pkey_{nullptr, EVP_PKEY_free};
    std::string last_error_;
    std::string peer_fingerprint_;
    std::string negotiated_alpn_;
    std::string negotiated_tls_version_;
    std::string negotiated_cipher_;
    std::string requested_server_name_;
    bool enable_ech_grease_ = true;
    bool ech_accepted_ = false;
    std::string ech_name_override_;
    std::vector<std::uint8_t> ech_retry_config_list_;
    bool connected_ = false;
};

} // namespace proxy
