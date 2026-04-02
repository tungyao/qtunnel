#pragma once

#include "common/logging.h"
#include "common/reactor.h"

#include <cstdint>
#include <string>

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
};

class ServerConnection;

struct SocketBinding {
    enum class Kind {
        Listener,
        Client,
        Upstream
    };

    Kind kind = Kind::Listener;
    ServerConnection* connection = nullptr;
    std::uint32_t stream_id = 0;
};
