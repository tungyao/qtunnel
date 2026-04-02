#pragma once

#include "common/reactor.h"
#include "common/tls_wrapper.h"
#include "common/tunnel_protocol.h"
#include "server_shared.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace server_upstream {

enum class State {
    Connecting,
    ProxyMethodWrite,
    ProxyMethodRead,
    ProxyConnectWrite,
    ProxyConnectReadHead,
    ProxyConnectReadDomainLength,
    ProxyConnectReadBody,
    Open
};

struct Peer {
    std::uint32_t id = 0;
    proxy::socket_t sock = proxy::kInvalidSocket;
    State state = State::Connecting;
    std::uint8_t requested_atyp = 0;
    std::string requested_host;
    std::uint16_t requested_port = 0;
    bool use_socks5 = false;
    std::vector<std::uint8_t> pending_uplink;
    std::size_t pending_uplink_offset = 0;
    std::vector<std::uint8_t> control_out;
    std::size_t control_out_offset = 0;
    std::vector<std::uint8_t> control_in;
    std::size_t control_expected = 0;
};

using DownlinkSink =
    std::function<void(proxy::FrameType, std::uint32_t, const std::vector<std::uint8_t>&)>;

proxy::EventFlags interest(const Peer& peer);

bool start_connect(const ServerConfig& config, std::uint32_t stream_id, std::uint8_t requested_atyp,
                   const std::string& requested_host, std::uint16_t requested_port, Peer& peer_out,
                   bool& connected, std::string& error);

bool finish_nonblocking_connect(Peer& peer, const DownlinkSink& downlink_sink);
bool process_write(Peer& peer, const DownlinkSink& downlink_sink);
bool process_read(Peer& peer, const DownlinkSink& downlink_sink);

void close(Peer& peer);
std::string describe_route(const ServerConfig& config, const std::string& requested_host, std::uint16_t requested_port);

} // namespace server_upstream
