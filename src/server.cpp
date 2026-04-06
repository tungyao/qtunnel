#include "common/logging.h"
#include "common/reactor.h"
#include "common/socks5.h"
#include "common/buffer_pool.h"
#include "server_connection.h"
#include "server_shared.h"

#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <atomic>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
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

std::atomic<std::uint64_t> g_connection_id{0};

#ifndef _WIN32
std::atomic<bool> g_sigchld_received{false};

void sigchld_handler(int sig) {
    (void)sig;
    g_sigchld_received = true;
}
#endif

std::string format_client_addr(sockaddr_storage* ss) {
    char buf[128] = {};
    std::uint16_t port = 0;
    if (ss->ss_family == AF_INET6) {
        auto* addr6 = reinterpret_cast<sockaddr_in6*>(ss);
        inet_ntop(AF_INET6, &addr6->sin6_addr, buf, sizeof(buf));
        port = ntohs(addr6->sin6_port);
    } else if (ss->ss_family == AF_INET) {
        auto* addr4 = reinterpret_cast<sockaddr_in*>(ss);
        inet_ntop(AF_INET, &addr4->sin_addr, buf, sizeof(buf));
        port = ntohs(addr4->sin_port);
    }
    return std::string(buf) + ":" + std::to_string(port);
}

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
#ifdef SO_REUSEPORT
    // Allow multiple processes to bind to the same port (for multi-worker model)
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char*>(&yes), sizeof(yes));
#endif
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

    ~ServerRuntime() {
        if (listener_ != kInvalidSocket) close_socket(listener_);
    }

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
        // Register listener fd
        fd_owners_[listener_] = FdOwner{FdOwner::Kind::Listener, nullptr, 0};
        if (!reactor_.arm(listener_, EventFlags::Readable, error)) {
            PROXY_LOG(Error, "[server] reactor arm listener failed: " << error);
            return false;
        }
        return true;
    }

    void run() {
        while (true) {
            std::string wait_error;
            const int ready = reactor_.wait(-1, wait_error);
            if (ready < 0) {
                if (wait_error.find("Interrupted") != std::string::npos ||
                    wait_error.find("EINTR") != std::string::npos) continue;
                PROXY_LOG(Error, "[server] reactor wait failed: " << wait_error);
                return;
            }

            // Dispatch events using fd_owners_ direct lookup
            for (int i = 0; i < ready; ++i) {
                const socket_t fd = reactor_.ready_fd(i);
                const EventFlags events = reactor_.ready_events(i);
                auto it = fd_owners_.find(fd);
                if (it == fd_owners_.end()) continue;

                const bool readable = (events & EventFlags::Readable) != EventFlags::None;
                const bool writable = (events & EventFlags::Writable) != EventFlags::None;
                const FdOwner& owner = it->second;

                if (owner.kind == FdOwner::Kind::Listener) {
                    accept_ready_clients();
                } else if (owner.kind == FdOwner::Kind::Client) {
                    owner.conn->on_client_event(readable, writable);
                } else {
                    owner.conn->on_upstream_event(owner.h2_stream_id, readable, writable);
                }
            }

            // After all I/O: flush H2 session sends and rearm upstream interests
            for (auto& kv : connections_) {
                if (!kv.second->closed()) {
                    kv.second->drive_session_send();
                    kv.second->rearm_all_upstreams();
                }
            }

            cleanup_closed_connections();
        }
    }

private:
    RuntimeHooks make_hooks() {
        return RuntimeHooks{
            [this]() -> Reactor& { return reactor_; },
            [this](socket_t fd, ServerConnection* conn, int32_t h2_stream_id) {
                fd_owners_[fd] = FdOwner{FdOwner::Kind::Upstream, conn, h2_stream_id};
                // Initial arm: readable + writable for connect-in-progress
                std::string err;
                reactor_.arm(fd, EventFlags::Readable | EventFlags::Writable, err);
            },
            [this](socket_t fd) {
                std::string err;
                reactor_.disarm(fd, err);
                fd_owners_.erase(fd);
            },
            [this]() -> proxy::DnsResolver* { return nullptr; },  // DNS resolver not yet initialized
            [this]() -> proxy::BufferPool* { return &buffer_pool_; }
        };
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

            std::string client_addr = format_client_addr(&ss);
            std::uint64_t conn_id = ++g_connection_id;
            PROXY_LOG(Info, "[server] client connected conn_id=" << conn_id << " from=" << client_addr);

            std::string err;
            if (!set_socket_nonblocking(client, true, err)) {
                PROXY_LOG(Error, "[server] set client nonblocking failed: " << err);
                close_socket(client);
                continue;
            }

            auto connection = std::make_unique<ServerConnection>(client, config_, make_hooks(), conn_id, client_addr);
            if (!connection->start()) {
                PROXY_LOG(Error, "[server] failed to start accepted connection conn_id=" << conn_id);
                continue;
            }

            socket_t fd = connection->client_fd();
            fd_owners_[fd] = FdOwner{FdOwner::Kind::Client, connection.get(), 0};
            if (!reactor_.arm(fd, EventFlags::Readable | EventFlags::Writable, err)) {
                PROXY_LOG(Error, "[server] reactor arm client failed: " << err);
                continue;
            }
            connections_[fd] = std::move(connection);
            PROXY_LOG(Info, "[server] client registered fd=" << fd << " conn_id=" << conn_id);
        }
    }

    void cleanup_closed_connections() {
        for (auto it = connections_.begin(); it != connections_.end();) {
            if (!it->second->closed()) { ++it; continue; }
            socket_t fd = it->first;
            PROXY_LOG(Info, "[server] cleaning up closed connection fd=" << fd);
            std::string err;
            reactor_.disarm(fd, err);
            fd_owners_.erase(fd);
            it = connections_.erase(it);
        }
    }

    ServerConfig config_;
    socket_t listener_ = kInvalidSocket;
    Reactor reactor_;
    proxy::BufferPool buffer_pool_{512};  // Support up to 512 blocks (32MB total)
    std::unordered_map<socket_t, FdOwner> fd_owners_;
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
        } else if (arg == "--workers" && i + 1 < argc) {
            cfg.worker_count = std::stoi(argv[++i]);
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
                 "[--target <host:port>] [--target-type direct|socks5|raw] [--workers <num>]\n"
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

    ServerConfig config = parse_args(argc, argv);
    set_log_level(config.log_level);

    PROXY_LOG(Info, "server starting log_level=" << proxy::log_level_name(config.log_level));

#ifndef _WIN32
    // Determine number of workers (default: CPU count)
    if (config.worker_count <= 0) {
        config.worker_count = static_cast<int>(std::thread::hardware_concurrency());
        if (config.worker_count <= 0) config.worker_count = 1;
    }

    // Master process with multiple workers
    if (config.worker_count > 1) {
        std::vector<pid_t> worker_pids;

        // Set up SIGCHLD handler to reap zombie processes
        signal(SIGCHLD, sigchld_handler);
        signal(SIGPIPE, SIG_IGN);  // Ignore broken pipe

        PROXY_LOG(Info, "server spawning " << config.worker_count << " worker processes");

        // Fork worker processes
        for (int i = 0; i < config.worker_count; ++i) {
            pid_t pid = fork();
            if (pid < 0) {
                PROXY_LOG(Error, "fork failed for worker " << i);
                continue;
            }
            if (pid == 0) {
                // Child process (worker)
                config.worker_id = i;
                PROXY_LOG(Info, "worker " << i << " starting (PID=" << getpid() << ")");

                ServerRuntime runtime(config);
                if (!runtime.init()) return 1;

                PROXY_LOG(Info, "worker " << i << " listening on 0.0.0.0/[::]:" << config.listen_port);
                runtime.run();
                return 0;
            }
            // Parent process
            worker_pids.push_back(pid);
        }

        // Master process: wait for workers and reap zombies
        PROXY_LOG(Info, "server master process (PID=" << getpid() << ") ready, "
                      << worker_pids.size() << " workers spawned");

        while (true) {
            if (g_sigchld_received) {
                g_sigchld_received = false;
                int status;
                while (waitpid(-1, &status, WNOHANG) > 0) {
                    // Reap zombie processes
                }
            }
            sleep(1);
        }
        return 0;
    }
#endif

    // Single-process mode
    PROXY_LOG(Info, "server running in single-process mode");

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
