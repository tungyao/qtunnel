#include "dns_resolver.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/eventfd.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <cstdio>

namespace proxy {

#ifdef _WIN32

// Windows stub implementation - DNS resolver not supported on Windows
DnsResolver::DnsResolver(int num_threads) {
    (void)num_threads;
    eventfd_ = -1;
}

DnsResolver::~DnsResolver() {}

int64_t DnsResolver::submit(const std::string& host, uint16_t port) {
    (void)host;
    (void)port;
    return -1;  // Not supported
}

std::vector<DnsResolver::Result> DnsResolver::drain_results() {
    return {};
}

void DnsResolver::worker_thread_main() {}

#else

// Linux/Unix implementation with eventfd, thread pool, and TTL cache
DnsResolver::DnsResolver(int num_threads) {
    // Create eventfd for signaling completion
    eventfd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (eventfd_ < 0) {
        throw std::runtime_error("Failed to create eventfd for DNS resolver");
    }

    // Spawn worker threads
    for (int i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&DnsResolver::worker_thread_main, this);
    }
}

DnsResolver::~DnsResolver() {
    // Signal workers to shut down
    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        shutdown_ = true;
    }
    job_cv_.notify_all();

    // Wait for all workers to finish
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }

    // Close eventfd
    if (eventfd_ >= 0) {
        close(eventfd_);
        eventfd_ = -1;
    }
}

void DnsResolver::sort_ipv4_first(std::vector<sockaddr_storage>& addrs) {
    std::stable_sort(addrs.begin(), addrs.end(),
        [](const sockaddr_storage& a, const sockaddr_storage& b) {
            const bool a_v4 = (a.ss_family == AF_INET);
            const bool b_v4 = (b.ss_family == AF_INET);
            return a_v4 && !b_v4;  // IPv4 < IPv6 in ordering
        });
}

void DnsResolver::post_result(Result result) {
    {
        std::lock_guard<std::mutex> lock(result_mutex_);
        completed_results_.push(std::move(result));
    }
    uint64_t counter = 1;
    ssize_t _w = write(eventfd_, &counter, sizeof(counter)); (void)_w;
}

int64_t DnsResolver::submit(const std::string& host, uint16_t port) {
    // Check cache before hitting the network
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = cache_.find(host);
        if (it != cache_.end() &&
            it->second.expiry > std::chrono::steady_clock::now()) {
            // Cache hit: post result immediately without spawning a job
            const int64_t job_id = next_job_id_.fetch_add(1);
            Result result;
            result.job_id = job_id;
            result.host   = host;
            result.port   = port;
            result.addrs  = it->second.addrs;  // Already IPv4-first sorted
            post_result(std::move(result));
            return job_id;
        }
        // Expired entry: evict lazily
        if (it != cache_.end()) {
            cache_.erase(it);
        }
    }

    // Cache miss: enqueue to worker thread
    const int64_t job_id = next_job_id_.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        pending_jobs_.push(Job{job_id, host, port});
    }
    job_cv_.notify_one();
    return job_id;
}

std::vector<DnsResolver::Result> DnsResolver::drain_results() {
    // Clear the eventfd counter (read all accumulated increments)
    uint64_t counter = 0;
    ssize_t _r = read(eventfd_, &counter, sizeof(counter)); (void)_r;

    std::vector<Result> results;
    std::lock_guard<std::mutex> lock(result_mutex_);
    while (!completed_results_.empty()) {
        results.push_back(std::move(completed_results_.front()));
        completed_results_.pop();
    }
    return results;
}

void DnsResolver::worker_thread_main() {
    while (true) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(job_mutex_);
            job_cv_.wait(lock, [this]() { return !pending_jobs_.empty() || shutdown_; });
            if (shutdown_ && pending_jobs_.empty()) break;
            if (pending_jobs_.empty()) continue;
            job = std::move(pending_jobs_.front());
            pending_jobs_.pop();
        }

        // Perform DNS resolution (blocking, no lock held)
        Result result;
        result.job_id = job.id;
        result.host   = job.host;
        result.port   = job.port;

        // Try IPv4 first, then IPv6 as fallback
        struct addrinfo hints {};
        hints.ai_socktype = SOCK_STREAM;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%u", job.port);

        hints.ai_family = AF_INET;
        struct addrinfo* res4 = nullptr;
        if (getaddrinfo(job.host.c_str(), port_str, &hints, &res4) == 0) {
            for (struct addrinfo* ai = res4; ai != nullptr; ai = ai->ai_next) {
                sockaddr_storage sa{};
                std::memcpy(&sa, ai->ai_addr, ai->ai_addrlen);
                result.addrs.push_back(sa);
            }
            freeaddrinfo(res4);
        }

        hints.ai_family = AF_INET6;
        struct addrinfo* res6 = nullptr;
        if (getaddrinfo(job.host.c_str(), port_str, &hints, &res6) == 0) {
            for (struct addrinfo* ai = res6; ai != nullptr; ai = ai->ai_next) {
                sockaddr_storage sa{};
                std::memcpy(&sa, ai->ai_addr, ai->ai_addrlen);
                result.addrs.push_back(sa);
            }
            freeaddrinfo(res6);
        }

        // Ensure IPv4 addresses are first (in case OS returned mixed results)
        sort_ipv4_first(result.addrs);

        // Store in cache if we got at least one address
        if (!result.addrs.empty()) {
            const auto expiry = std::chrono::steady_clock::now()
                              + std::chrono::seconds(kCacheTtlSeconds);
            std::lock_guard<std::mutex> lock(cache_mutex_);
            cache_[job.host] = CacheEntry{result.addrs, expiry};
        }

        post_result(std::move(result));
    }
}

#endif  // _WIN32

}  // namespace proxy
