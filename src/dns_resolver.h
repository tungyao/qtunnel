#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

namespace proxy {

class DnsResolver {
public:
    static constexpr int kCacheTtlSeconds = 600;  // 10 minutes

    struct Result {
        int64_t job_id;
        std::string host;
        uint16_t port;
        std::vector<sockaddr_storage> addrs;  // IPv4 first, empty if resolution failed
    };

    explicit DnsResolver(int num_threads = 2);
    ~DnsResolver();

    DnsResolver(const DnsResolver&) = delete;
    DnsResolver& operator=(const DnsResolver&) = delete;

    // Register eventfd with reactor - must be called to set up signaling
    int get_eventfd() const { return eventfd_; }

    // Submit a DNS resolution task (non-blocking), returns job_id.
    // Cache hit: result posted immediately to completed queue; no thread used.
    int64_t submit(const std::string& host, uint16_t port);

    // Drain all completed results from the results queue.
    // Call this when eventfd becomes readable.
    std::vector<Result> drain_results();

private:
    struct Job {
        int64_t id;
        std::string host;
        uint16_t port;
    };

    struct CacheEntry {
        std::vector<sockaddr_storage> addrs;
        std::chrono::steady_clock::time_point expiry;
    };

    void worker_thread_main();
    // Sort addrs so IPv4 (AF_INET) comes before IPv6 (AF_INET6)
    static void sort_ipv4_first(std::vector<sockaddr_storage>& addrs);
    // Post a result to completed_results_ and signal the eventfd (caller must NOT hold result_mutex_)
    void post_result(Result result);

    int eventfd_;  // For waking up the reactor
    std::atomic<int64_t> next_job_id_{1};

    // Job queue (worker threads)
    std::mutex job_mutex_;
    std::queue<Job> pending_jobs_;
    std::condition_variable job_cv_;
    bool shutdown_{false};

    // Results queue (main thread drains via drain_results)
    std::mutex result_mutex_;
    std::queue<Result> completed_results_;

    // DNS cache (host → addrs + expiry)
    std::mutex cache_mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;

    // Thread pool
    std::vector<std::thread> workers_;
};

}  // namespace proxy
