#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace proxy {

class Obfuscator {
public:
    Obfuscator()
        : rng_(std::random_device{}()),
          padding_dist_(10, 200),
          delay_dist_(0, 50),
          byte_dist_(0, 255) {}

    std::vector<std::uint8_t> wrap_payload(const std::vector<std::uint8_t>& clear) {
        const std::uint32_t clear_len = static_cast<std::uint32_t>(clear.size());
        const std::size_t padding_len = static_cast<std::size_t>(random_padding_length());

        std::vector<std::uint8_t> out(4 + clear.size() + padding_len, 0);
        out[0] = static_cast<std::uint8_t>((clear_len >> 24) & 0xff);
        out[1] = static_cast<std::uint8_t>((clear_len >> 16) & 0xff);
        out[2] = static_cast<std::uint8_t>((clear_len >> 8) & 0xff);
        out[3] = static_cast<std::uint8_t>(clear_len & 0xff);
        std::copy(clear.begin(), clear.end(), out.begin() + 4);
        fill_random(out.data() + 4 + clear.size(), padding_len);
        return out;
    }

    bool unwrap_payload(const std::vector<std::uint8_t>& wrapped, std::vector<std::uint8_t>& clear) const {
        if (wrapped.size() < 4) {
            return false;
        }
        const std::uint32_t clear_len =
            (static_cast<std::uint32_t>(wrapped[0]) << 24) |
            (static_cast<std::uint32_t>(wrapped[1]) << 16) |
            (static_cast<std::uint32_t>(wrapped[2]) << 8) |
            static_cast<std::uint32_t>(wrapped[3]);
        if (wrapped.size() < 4 + clear_len) {
            return false;
        }
        clear.assign(wrapped.begin() + 4, wrapped.begin() + 4 + clear_len);
        return true;
    }

    void maybe_delay(bool critical = false) {
        if (critical) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(random_delay_ms()));
    }

    std::array<std::uint8_t, 8> make_http2_ping_payload() {
        std::array<std::uint8_t, 8> ping{};
        fill_random(ping.data(), ping.size());
        return ping;
    }

    std::vector<std::uint8_t> make_warmup_payload() {
        std::vector<std::uint8_t> out(static_cast<std::size_t>(random_padding_length()), 0);
        fill_random(out.data(), out.size());
        return out;
    }

private:
    int random_padding_length() {
        std::lock_guard<std::mutex> lock(mutex_);
        return padding_dist_(rng_);
    }

    int random_delay_ms() {
        std::lock_guard<std::mutex> lock(mutex_);
        return delay_dist_(rng_);
    }

    void fill_random(void* data, std::size_t len) {
        auto* p = static_cast<std::uint8_t*>(data);
        std::lock_guard<std::mutex> lock(mutex_);
        for (std::size_t i = 0; i < len; ++i) {
            p[i] = static_cast<std::uint8_t>(byte_dist_(rng_));
        }
    }

    mutable std::mutex mutex_;
    std::mt19937 rng_;
    std::uniform_int_distribution<int> padding_dist_;
    std::uniform_int_distribution<int> delay_dist_;
    std::uniform_int_distribution<int> byte_dist_;
};

} // namespace proxy
