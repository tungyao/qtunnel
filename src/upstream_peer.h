#pragma once

#include "common/reactor.h"
#include "common/tls_wrapper.h"
#include "common/buffer_pool.h"
#include "server_shared.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <string>
#include <vector>

namespace server_upstream {

struct ChunkQueue {
    static constexpr std::size_t kHighWater = 512 * 1024;
    static constexpr std::size_t kLowWater  = 128 * 1024;

    struct Slot {
        proxy::BufferPool::Block* block;
        std::size_t offset;  // Read position within this block
    };

    std::deque<Slot> slots;
    std::size_t total_bytes = 0;
    proxy::BufferPool* pool = nullptr;  // Pointer to shared pool (no ownership)

    void push(proxy::BufferPool::Block* block) {
        if (!block || block->used == 0) return;
        total_bytes += block->used;
        slots.push_back(Slot{block, 0});
    }

    // Consume up to `want` bytes into dst. Returns bytes consumed.
    std::size_t consume(uint8_t* dst, std::size_t want) {
        if (slots.empty() || want == 0 || !pool) return 0;

        std::size_t consumed = 0;
        while (consumed < want && !slots.empty()) {
            Slot& front_slot = slots.front();
            const std::size_t avail = front_slot.block->used - front_slot.offset;
            const std::size_t n = (want - consumed < avail) ? (want - consumed) : avail;

            std::memcpy(dst + consumed,
                       front_slot.block->data + front_slot.offset, n);
            front_slot.offset += n;
            consumed += n;
            total_bytes -= n;

            if (front_slot.offset >= front_slot.block->used) {
                // This block is fully consumed, release it back to pool
                proxy::BufferPool::Block* released = front_slot.block;
                slots.pop_front();
                pool->release(released);
            }
        }
        return consumed;
    }

    bool empty()            const { return total_bytes == 0; }
    bool above_high_water() const { return total_bytes >= kHighWater; }
    bool below_low_water()  const { return total_bytes <= kLowWater; }
};

enum class State {
    DnsPending,              // Waiting for DNS resolution to complete
    Connecting,              // TCP connect in progress
    ProxyMethodWrite,
    ProxyMethodRead,
    ProxyConnectWrite,
    ProxyConnectReadHead,
    ProxyConnectReadDomainLength,
    ProxyConnectReadBody,
    Open
};

struct Peer {
    int32_t  h2_stream_id = 0;
    proxy::socket_t sock  = proxy::kInvalidSocket;
    State state = State::Connecting;  // Start in Connecting; DnsPending support not yet implemented

    // DNS resolution (for async DNS) - not yet implemented
    int64_t dns_job_id = -1;  // Job ID from DnsResolver, or -1 if not pending DNS

    // Buffer pool reference (set by caller, not owned)
    proxy::BufferPool* buffer_pool = nullptr;

    // Downstream (upstream -> client)
    ChunkQueue pending_downlink;
    bool upstream_eof      = false;  // upstream closed, drain then send END_STREAM
    bool downlink_deferred = false;  // nghttp2 data_provider returned DEFERRED

    // Upstream (client -> upstream)
    std::vector<uint8_t> pending_uplink;
    std::size_t pending_uplink_offset = 0;
    std::size_t unconsumed_uplink_bytes = 0;  // bytes received but not yet written to upstream

    // SOCKS5 fields
    bool use_socks5 = false;
    std::uint8_t  requested_atyp = 0;
    std::string   requested_host;
    std::uint16_t requested_port = 0;
    std::vector<uint8_t> control_out;
    std::size_t          control_out_offset = 0;
    std::vector<uint8_t> control_in;
    std::size_t          control_expected = 0;
};

proxy::EventFlags interest(const Peer& peer);

bool start_connect(const ServerConfig& config, int32_t h2_stream_id,
                   std::uint8_t requested_atyp,
                   const std::string& requested_host, std::uint16_t requested_port,
                   Peer& peer_out, bool& connected, std::string& error,
                   proxy::DnsResolver* dns_resolver = nullptr);

bool finish_nonblocking_connect(Peer& peer, bool& send_open_ok, std::string& error);
bool process_write(Peer& peer);          // returns false on fatal error
bool process_read(Peer& peer);           // returns false on EOF/error

void close(Peer& peer);
std::string describe_route(const ServerConfig& config,
                            const std::string& requested_host,
                            std::uint16_t requested_port);

} // namespace server_upstream
