#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#else
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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

enum class EventFlags : std::uint32_t {
    None = 0,
    Readable = 1 << 0,
    Writable = 1 << 1,
    ReadableWritable = Readable | Writable,
};

inline EventFlags operator|(EventFlags a, EventFlags b) {
    return static_cast<EventFlags>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

inline EventFlags operator&(EventFlags a, EventFlags b) {
    return static_cast<EventFlags>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}

struct FdEvent {
    socket_t fd = kInvalidSocket;
    EventFlags events = EventFlags::None;
};

class Reactor {
public:
    Reactor();
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    bool init(std::string& error);

    bool add(socket_t fd, EventFlags events, std::string& error);
    bool modify(socket_t fd, EventFlags events, std::string& error);
    bool remove(socket_t fd, std::string& error);

    // Idempotent arm: only calls epoll_ctl when flags actually change
    bool arm(socket_t fd, EventFlags events, std::string& error);
    bool disarm(socket_t fd, std::string& error);

    int wait(int timeout_ms, std::string& error);

    int ready_count() const { return ready_count_; }

    socket_t ready_fd(int index) const;
    EventFlags ready_events(int index) const;

    void clear_ready();

private:
    std::unordered_map<socket_t, EventFlags> registered_;
#ifdef _WIN32
    struct PollFd {
        WSAPOLLFD pollfd;
        socket_t fd;
    };
    std::vector<PollFd> poll_fds_;
#else
    int epoll_fd_ = -1;
    std::vector<struct epoll_event> epoll_events_;
#endif

    int ready_count_ = 0;
};

inline EventFlags socket_readable_events(EventFlags flags) {
    return flags & EventFlags::Readable;
}

inline EventFlags socket_writable_events(EventFlags flags) {
    return flags & EventFlags::Writable;
}

} // namespace proxy
