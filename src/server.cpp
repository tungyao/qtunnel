#include "common/logging.h"
#include "common/reactor.h"
#include "server_connection.h"
#include "server_shared.h"

#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace {

using proxy::close_socket;
using proxy::EventFlags;
using proxy::kInvalidSocket;
using proxy::LogLevel;
using proxy::parse_log_level;
using proxy::Reactor;
using proxy::set_log_level;
using proxy::set_socket_nonblocking;
using proxy::socket_t;

bool is_socket_would_block(int code) {
#ifdef _WIN32
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS;
#else
    return code == EAGAIN || code == EWOULDBLOCK || code == EINPROGRESS;
#endif
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

socket_t make_listener(std::uint16_t port) {
    socket_t sock = static_cast<socket_t>(::socket(AF_INET6, SOCK_STREAM, 0));
    if (sock == kInvalidSocket) return kInvalidSocket;

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
    if (::listen(sock, 1024) != 0) {
        close_socket(sock);
        return kInvalidSocket;
    }
    return sock;
}

class ServerRuntime {
public:
    explicit ServerRuntime(ServerConfig config) : config_(std::move(config)) {}

    bool init() {
        listener_ = make_listener(config_.listen_port);
        if (listener_ == kInvalidSocket) {
            PROXY_LOG(Error, "[server] make_listener failed on port " << config_.listen_port);
            return false;
        }
        std::string error;
        if (!set_socket_nonblocking(listener_, true, error)) {
            PROXY_LOG(Error, "[server] set listener nonblocking failed: " << error);
            return false;
        }
        if (!reactor_.init(error)) {
            PROXY_LOG(Error, "[server] reactor init failed: " << error);
            return false;
        }
        return true;
    }

    ~ServerRuntime() {
        if (listener_ != kInvalidSocket) close_socket(listener_);
    }

    void run() {
        while (true) {
            std::map<socket_t, EventFlags> desired;
            std::map<socket_t, SocketBinding> bindings;
            desired[listener_] = EventFlags::Readable;
            bindings[listener_] = SocketBinding{SocketBinding::Kind::Listener, nullptr, 0};

            for (auto& kv : connections_) {
                kv.second->collect_watches(desired, bindings);
            }

            if (!sync_reactor(desired)) {
                PROXY_LOG(Error, "[server] sync_reactor failed, runtime exiting");
                return;
            }

            std::string wait_error;
            const int ready = reactor_.wait(-1, wait_error);
            if (ready < 0) {
                PROXY_LOG(Error, "[server] reactor wait failed: " << wait_error);
                return;
            }

            for (int i = 0; i < ready; ++i) {
                const socket_t fd = reactor_.ready_fd(i);
                const EventFlags events = reactor_.ready_events(i);
                const auto binding_it = bindings.find(fd);
                if (binding_it == bindings.end()) continue;

                const bool readable = (events & EventFlags::Readable) != EventFlags::None;
                const bool writable = (events & EventFlags::Writable) != EventFlags::None;
                if (binding_it->second.kind == SocketBinding::Kind::Listener) {
                    accept_ready_clients();
                } else if (binding_it->second.kind == SocketBinding::Kind::Client) {
                    binding_it->second.connection->on_client_event(readable, writable, false, false);
                } else {
                    binding_it->second.connection->on_upstream_event(binding_it->second.stream_id, readable, writable,
                                                                     false, false);
                }
            }

            cleanup_closed_connections();
        }
    }

private:
    bool sync_reactor(const std::map<socket_t, EventFlags>& desired) {
        std::string error;
        for (auto it = watched_.begin(); it != watched_.end();) {
            if (desired.find(it->first) == desired.end()) {
                if (!reactor_.remove(it->first, error)) {
                    PROXY_LOG(Error, "[server] reactor remove failed fd=" << it->first << " error=" << error);
                    return false;
                }
                it = watched_.erase(it);
            } else {
                ++it;
            }
        }

        for (const auto& kv : desired) {
            const auto it = watched_.find(kv.first);
            if (it == watched_.end()) {
                if (!reactor_.add(kv.first, kv.second, error)) {
                    PROXY_LOG(Error, "[server] reactor add failed fd=" << kv.first << " error=" << error);
                    return false;
                }
                watched_[kv.first] = kv.second;
            } else if (it->second != kv.second) {
                if (!reactor_.modify(kv.first, kv.second, error)) {
                    PROXY_LOG(Error, "[server] reactor modify failed fd=" << kv.first << " error=" << error);
                    return false;
                }
                it->second = kv.second;
            }
        }

        return true;
    }

    void accept_ready_clients() {
        while (true) {
            sockaddr_storage ss{};
            socklen_t slen = sizeof(ss);
            socket_t client = ::accept(listener_, reinterpret_cast<sockaddr*>(&ss), &slen);
            if (client == kInvalidSocket) {
                const int code = proxy::last_socket_error_code();
                if (is_socket_would_block(code)) return;
                PROXY_LOG(Error, "[server] accept failed: " << proxy::socket_error_string());
                return;
            }

            auto connection = std::make_unique<ServerConnection>(client, config_);
            if (!connection->start()) {
                PROXY_LOG(Error, "[server] failed to start accepted connection");
                continue;
            }
            connections_[connection->client_socket()] = std::move(connection);
        }
    }

    void cleanup_closed_connections() {
        for (auto it = connections_.begin(); it != connections_.end();) {
            if (!it->second->closed()) ++it;
            else it = connections_.erase(it);
        }
    }

    ServerConfig config_;
    socket_t listener_ = kInvalidSocket;
    Reactor reactor_;
    std::map<socket_t, EventFlags> watched_;
    std::map<socket_t, std::unique_ptr<ServerConnection>> connections_;
};

ServerConfig parse_args(int argc, char** argv) {
    ServerConfig cfg;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--listen" && i + 1 < argc) cfg.listen_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        else if (arg == "--cert-file" && i + 1 < argc) cfg.cert_file = argv[++i];
        else if (arg == "--key-file" && i + 1 < argc) cfg.key_file = argv[++i];
        else if (arg == "--auth-password" && i + 1 < argc) cfg.auth_password = argv[++i];
        else if (arg == "--log-level" && i + 1 < argc) {
            LogLevel level = LogLevel::Info;
            if (parse_log_level(argv[++i], level)) cfg.log_level = level;
        } else if (arg == "--target" && i + 1 < argc) {
            cfg.has_fixed_target = parse_host_port(argv[++i], cfg.fixed_host, cfg.fixed_port);
            if (cfg.has_fixed_target) cfg.target_type = ServerConfig::TargetType::Socks5;
        } else if (arg == "--target-type" && i + 1 < argc) {
            const std::string type = argv[++i];
            if (type == "raw") cfg.target_type = ServerConfig::TargetType::Raw;
            else if (type == "socks5") cfg.target_type = ServerConfig::TargetType::Socks5;
            else if (type == "direct") cfg.target_type = ServerConfig::TargetType::Direct;
        } else if (!arg.empty() && arg[0] != '-') {
            cfg.has_fixed_target = parse_host_port(arg, cfg.fixed_host, cfg.fixed_port);
            if (cfg.has_fixed_target) cfg.target_type = ServerConfig::TargetType::Socks5;
        }
    }
    return cfg;
}

void print_usage() {
    std::cout << "Usage:\n"
              << "  server [--listen <port>] [--cert-file <cert.pem>] [--key-file <key.pem>] "
                 "[--target <host:port>] [--target-type direct|socks5|raw]\n"
              << "  server <host:port>\n";
}

} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
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

    ServerRuntime runtime(config);
    if (!runtime.init()) return 1;

    PROXY_LOG(Info, "server listen 0.0.0.0/[::]:" << config.listen_port);
    if (config.has_fixed_target) {
        std::ostringstream target_desc;
        target_desc << "fixed upstream target: " << config.fixed_host << ":" << config.fixed_port;
        if (config.target_type == ServerConfig::TargetType::Raw) target_desc << " (raw)";
        else if (config.target_type == ServerConfig::TargetType::Socks5) target_desc << " (socks5)";
        else target_desc << " (direct)";
        PROXY_LOG(Info, target_desc.str());
    } else {
        PROXY_LOG(Info, "connect directly to requested upstream");
    }

    runtime.run();
    return 0;
}
