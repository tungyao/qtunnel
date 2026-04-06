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

// Linux/Unix implementation with eventfd and thread pool
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

int64_t DnsResolver::submit(const std::string& host, uint16_t port) {
    int64_t job_id;
    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        job_id = next_job_id_++;
        pending_jobs_.push(Job{job_id, host, port});
    }
    job_cv_.notify_one();
    return job_id;
}

std::vector<DnsResolver::Result> DnsResolver::drain_results() {
    // Clear the eventfd counter
    uint64_t counter = 0;
    (void)read(eventfd_, &counter, sizeof(counter));

    // Drain all results
    std::vector<Result> results;
    {
        std::lock_guard<std::mutex> lock(result_mutex_);
        while (!completed_results_.empty()) {
            results.push_back(std::move(completed_results_.front()));
            completed_results_.pop();
        }
    }
    return results;
}

void DnsResolver::worker_thread_main() {
    while (true) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(job_mutex_);
            // Wait for a job or shutdown signal
            job_cv_.wait(lock, [this]() { return !pending_jobs_.empty() || shutdown_; });

            if (shutdown_ && pending_jobs_.empty()) {
                break;
            }

            if (pending_jobs_.empty()) {
                continue;
            }

            job = std::move(pending_jobs_.front());
            pending_jobs_.pop();
        }

        // Perform DNS resolution (blocking, outside of lock)
        Result result;
        result.job_id = job.id;
        result.host = job.host;
        result.port = job.port;

        struct addrinfo hints {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo* res = nullptr;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%u", job.port);

        // Try IPv4 first
        if (getaddrinfo(job.host.c_str(), port_str, &hints, &res) == 0) {
            for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
                sockaddr_storage sa;
                std::memcpy(&sa, ai->ai_addr, ai->ai_addrlen);
                result.addrs.push_back(sa);
            }
            freeaddrinfo(res);
        }

        // Post result and signal reactor
        {
            std::lock_guard<std::mutex> lock(result_mutex_);
            completed_results_.push(std::move(result));
        }

        // Signal the reactor via eventfd
        uint64_t counter = 1;
        (void)write(eventfd_, &counter, sizeof(counter));
    }
}

#endif  // _WIN32

}  // namespace proxy
