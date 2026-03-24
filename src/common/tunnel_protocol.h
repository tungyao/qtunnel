#pragma once

#include "socks5.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace proxy {

enum class FrameType : std::uint8_t {
    Open = 1,
    OpenOk = 2,
    OpenFail = 3,
    Data = 4,
    Close = 5,
    Ping = 6,
    Pong = 7
};

struct FrameHeader {
    std::uint8_t type = 0;
    std::uint32_t stream_id = 0;
    std::uint32_t payload_len = 0;
};

inline std::uint32_t to_be32(std::uint32_t v) {
    return ((v & 0x000000ffU) << 24) |
           ((v & 0x0000ff00U) << 8) |
           ((v & 0x00ff0000U) >> 8) |
           ((v & 0xff000000U) >> 24);
}

inline std::vector<std::uint8_t> to_bytes(const std::string& text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

inline void append_frame(std::vector<std::uint8_t>& buffer, FrameType type, std::uint32_t stream_id,
                         const std::vector<std::uint8_t>& payload) {
    FrameHeader header{};
    header.type = static_cast<std::uint8_t>(type);
    header.stream_id = to_be32(stream_id);
    header.payload_len = to_be32(static_cast<std::uint32_t>(payload.size()));
    const auto* head_ptr = reinterpret_cast<const std::uint8_t*>(&header);
    buffer.insert(buffer.end(), head_ptr, head_ptr + sizeof(header));
    buffer.insert(buffer.end(), payload.begin(), payload.end());
}

inline bool parse_frames(const std::vector<std::uint8_t>& buffer,
                         std::vector<std::pair<FrameHeader, std::vector<std::uint8_t>>>& out) {
    std::size_t offset = 0;
    while (offset + sizeof(FrameHeader) <= buffer.size()) {
        FrameHeader header{};
        std::memcpy(&header, buffer.data() + offset, sizeof(header));
        offset += sizeof(header);
        const std::uint32_t payload_len = to_be32(header.payload_len);
        if (offset + payload_len > buffer.size()) {
            return false;
        }
        out.push_back({
            header,
            std::vector<std::uint8_t>(buffer.begin() + static_cast<std::ptrdiff_t>(offset),
                                      buffer.begin() + static_cast<std::ptrdiff_t>(offset + payload_len))
        });
        offset += payload_len;
    }
    return offset == buffer.size();
}

inline bool consume_frames(std::vector<std::uint8_t>& buffer,
                           std::vector<std::pair<FrameHeader, std::vector<std::uint8_t>>>& out) {
    std::size_t offset = 0;
    while (offset + sizeof(FrameHeader) <= buffer.size()) {
        FrameHeader header{};
        std::memcpy(&header, buffer.data() + offset, sizeof(header));
        const std::uint32_t payload_len = to_be32(header.payload_len);
        if (offset + sizeof(FrameHeader) + payload_len > buffer.size()) {
            break;
        }

        offset += sizeof(FrameHeader);
        out.push_back({
            header,
            std::vector<std::uint8_t>(buffer.begin() + static_cast<std::ptrdiff_t>(offset),
                                      buffer.begin() + static_cast<std::ptrdiff_t>(offset + payload_len))
        });
        offset += payload_len;
    }

    if (offset == 0) {
        return true;
    }
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(offset));
    return true;
}

inline std::vector<std::uint8_t> encode_open_request(const Socks5Request& req) {
    std::vector<std::uint8_t> out;
    out.push_back(req.atyp);
    out.push_back(static_cast<std::uint8_t>((req.port >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(req.port & 0xff));
    const std::uint16_t host_len = static_cast<std::uint16_t>(req.host.size());
    out.push_back(static_cast<std::uint8_t>((host_len >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(host_len & 0xff));
    out.insert(out.end(), req.host.begin(), req.host.end());
    return out;
}

inline bool decode_open_request(const std::vector<std::uint8_t>& clear, std::uint8_t& atyp,
                                std::string& host, std::uint16_t& port) {
    if (clear.size() < 5) {
        return false;
    }
    atyp = clear[0];
    port = static_cast<std::uint16_t>((clear[1] << 8) | clear[2]);
    const std::uint16_t host_len = static_cast<std::uint16_t>((clear[3] << 8) | clear[4]);
    if (clear.size() < 5U + host_len) {
        return false;
    }
    host.assign(reinterpret_cast<const char*>(clear.data() + 5), host_len);
    return true;
}

inline std::vector<std::uint8_t> encode_open_ok() {
    return {0x00};
}

inline std::vector<std::uint8_t> encode_open_fail(const std::string& reason) {
    const std::string clipped = reason.substr(0, 250);
    std::vector<std::uint8_t> out(1 + clipped.size(), 0);
    out[0] = static_cast<std::uint8_t>(clipped.size());
    std::memcpy(out.data() + 1, clipped.data(), clipped.size());
    return out;
}

inline bool decode_open_fail(const std::vector<std::uint8_t>& clear, std::string& reason) {
    if (clear.empty()) {
        reason = "unknown";
        return true;
    }
    const std::size_t len = clear[0];
    if (clear.size() < 1 + len) {
        return false;
    }
    reason.assign(reinterpret_cast<const char*>(clear.data() + 1), len);
    return true;
}

} // namespace proxy
