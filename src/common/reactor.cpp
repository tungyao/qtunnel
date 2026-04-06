#include "common/reactor.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/epoll.h>
#include <cstring>
#endif

namespace proxy {

Reactor::Reactor() {
#ifdef _WIN32
    poll_fds_.reserve(64);
#else
    epoll_events_.reserve(64);
#endif
}

Reactor::~Reactor() {
#ifndef _WIN32
    if (epoll_fd_ >= 0) {
        ::close(epoll_fd_);
        epoll_fd_ = -1;
    }
#endif
}

bool Reactor::init(std::string& error) {
#ifdef _WIN32
    (void)error;
    return true;
#else
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        error = "epoll_create1 failed: " + std::string(strerror(errno));
        return false;
    }
    return true;
#endif
}

bool Reactor::add(socket_t fd, EventFlags events, std::string& error) {
#ifdef _WIN32
    (void)error;
    short poll_events = 0;
    if ((events & EventFlags::Readable) != EventFlags::None) {
        poll_events |= POLLIN;
    }
    if ((events & EventFlags::Writable) != EventFlags::None) {
        poll_events |= POLLOUT;
    }

    for (auto& pfd : poll_fds_) {
        if (pfd.fd == fd) {
            pfd.pollfd.events = poll_events;
            return true;
        }
    }

    WSAPOLLFD wsa_pfd{};
    wsa_pfd.fd = fd;
    wsa_pfd.events = poll_events;
    poll_fds_.push_back({wsa_pfd, fd});
    return true;
#else
    std::uint32_t epoll_events = EPOLLET | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    if ((events & EventFlags::Readable) != EventFlags::None) {
        epoll_events |= EPOLLIN;
    }
    if ((events & EventFlags::Writable) != EventFlags::None) {
        epoll_events |= EPOLLOUT;
    }

    epoll_event ev{};
    ev.events = epoll_events;
    ev.data.fd = fd;

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        error = "epoll_ctl(ADD) failed for fd " + std::to_string(fd) + ": " + strerror(errno);
        return false;
    }
    return true;
#endif
}

bool Reactor::modify(socket_t fd, EventFlags events, std::string& error) {
#ifdef _WIN32
    (void)error;
    short poll_events = 0;
    if ((events & EventFlags::Readable) != EventFlags::None) {
        poll_events |= POLLIN;
    }
    if ((events & EventFlags::Writable) != EventFlags::None) {
        poll_events |= POLLOUT;
    }

    for (auto& pfd : poll_fds_) {
        if (pfd.fd == fd) {
            pfd.pollfd.events = poll_events;
            return true;
        }
    }

    WSAPOLLFD wsa_pfd{};
    wsa_pfd.fd = fd;
    wsa_pfd.events = poll_events;
    poll_fds_.push_back({wsa_pfd, fd});
    return true;
#else
    std::uint32_t epoll_events = EPOLLET | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    if ((events & EventFlags::Readable) != EventFlags::None) {
        epoll_events |= EPOLLIN;
    }
    if ((events & EventFlags::Writable) != EventFlags::None) {
        epoll_events |= EPOLLOUT;
    }

    epoll_event ev{};
    ev.events = epoll_events;
    ev.data.fd = fd;

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0) {
        error = "epoll_ctl(MOD) failed for fd " + std::to_string(fd) + ": " + strerror(errno);
        return false;
    }
    return true;
#endif
}

bool Reactor::remove(socket_t fd, std::string& error) {
#ifdef _WIN32
    (void)error;
    for (auto it = poll_fds_.begin(); it != poll_fds_.end(); ++it) {
        if (it->fd == fd) {
            poll_fds_.erase(it);
            return true;
        }
    }
    return true;
#else
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) < 0) {
        const int code = errno;
        if (code != ENOENT && code != EBADF) {
            error = "epoll_ctl(DEL) failed for fd " + std::to_string(fd) + ": " + strerror(code);
            return false;
        }
    }
    return true;
#endif
}

int Reactor::wait(int timeout_ms, std::string& error) {
#ifdef _WIN32
    if (poll_fds_.empty()) {
        if (timeout_ms < 0) {
            error = "no fds to poll";
            return -1;
        }
        if (timeout_ms > 0) {
            ::Sleep(static_cast<DWORD>(timeout_ms));
        }
        ready_count_ = 0;
        return 0;
    }

    std::vector<WSAPOLLFD> temp_fds(poll_fds_.size());
    for (std::size_t i = 0; i < poll_fds_.size(); ++i) {
        temp_fds[i] = poll_fds_[i].pollfd;
    }

    const int ret = ::WSAPoll(temp_fds.data(), static_cast<ULONG>(temp_fds.size()), timeout_ms);
    if (ret < 0) {
        error = "WSAPoll failed: " + std::to_string(WSAGetLastError());
        ready_count_ = 0;
        return -1;
    }

    ready_count_ = ret;
    for (int i = 0; i < ret; ++i) {
        poll_fds_[i].pollfd = temp_fds[i];
    }
    return ret;
#else
    if (epoll_fd_ < 0) {
        error = "epoll not initialized";
        return -1;
    }

    const int max_events = static_cast<int>(epoll_events_.capacity());
    epoll_events_.resize(max_events);

    const int ret = epoll_wait(epoll_fd_, epoll_events_.data(), max_events, timeout_ms);
    if (ret < 0) {
        if (errno == EINTR) {
            ready_count_ = 0;
            return 0;
        }
        error = "epoll_wait failed: " + std::string(strerror(errno));
        ready_count_ = 0;
        return -1;
    }

    ready_count_ = ret;
    return ret;
#endif
}

socket_t Reactor::ready_fd(int index) const {
#ifdef _WIN32
    if (index >= 0 && index < ready_count_) {
        return poll_fds_[index].fd;
    }
    return kInvalidSocket;
#else
    if (index >= 0 && index < ready_count_) {
        return epoll_events_[index].data.fd;
    }
    return kInvalidSocket;
#endif
}

EventFlags Reactor::ready_events(int index) const {
#ifdef _WIN32
    if (index >= 0 && index < ready_count_) {
        const short revents = poll_fds_[index].pollfd.revents;
        EventFlags flags = EventFlags::None;
        if (revents & (POLLIN | POLLHUP | POLLERR)) {
            flags = flags | EventFlags::Readable;
        }
        if (revents & POLLOUT) {
            flags = flags | EventFlags::Writable;
        }
        return flags;
    }
    return EventFlags::None;
#else
    if (index >= 0 && index < ready_count_) {
        const std::uint32_t ev = epoll_events_[index].events;
        EventFlags flags = EventFlags::None;
        if (ev & (EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR)) {
            flags = flags | EventFlags::Readable;
        }
        if (ev & EPOLLOUT) {
            flags = flags | EventFlags::Writable;
        }
        return flags;
    }
    return EventFlags::None;
#endif
}

void Reactor::clear_ready() {
    ready_count_ = 0;
}

bool Reactor::arm(socket_t fd, EventFlags events, std::string& error) {
    auto it = registered_.find(fd);
    if (it != registered_.end() && it->second == events) return true;
    bool ok = (it == registered_.end()) ? add(fd, events, error) : modify(fd, events, error);
    if (ok) registered_[fd] = events;
    return ok;
}

bool Reactor::disarm(socket_t fd, std::string& error) {
    if (registered_.erase(fd) == 0) return true;
    return remove(fd, error);
}

} // namespace proxy
