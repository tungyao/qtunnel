#pragma once

#include "common/logging.h"
#include "common/reactor.h"

#include <cstdint>
#include <functional>
#include <string>

namespace proxy {
    class DnsResolver;
    class BufferPool;
}

struct ServerConfig {
    enum class TargetType {
        Direct,
        Raw,
        Socks5
    };

    std::uint16_t listen_port = 8443;
    bool has_fixed_target = false;
    std::string fixed_host;
    std::uint16_t fixed_port = 0;
    TargetType target_type = TargetType::Direct;
    std::string cert_file;
    std::string key_file;
    std::string auth_password;
    proxy::LogLevel log_level = proxy::LogLevel::Info;
    int worker_id = -1;
    int worker_count = 0;
};

class ServerConnection;

struct FdOwner {
    enum class Kind { Listener, Client, Upstream, DnsEvent };
    Kind kind = Kind::Listener;
    ServerConnection* conn = nullptr;
    int32_t h2_stream_id = 0;  // valid when kind == Upstream
};

// Callbacks from ServerConnection into ServerRuntime for fd lifecycle management
struct RuntimeHooks {
    std::function<proxy::Reactor&()> get_reactor;
    std::function<void(proxy::socket_t, ServerConnection*, int32_t)> register_upstream;
    std::function<void(proxy::socket_t)> unregister_fd;
    std::function<proxy::DnsResolver*()> get_dns_resolver;
    std::function<proxy::BufferPool*()> get_buffer_pool;
    // Register a pending DNS job: job_id, client_fd of this connection, h2_stream_id
    std::function<void(int64_t, proxy::socket_t, int32_t)> register_dns_job;
};
