#pragma once

#include <cstdint>
#include <string>
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
    struct Result {
        int64_t job_id;
        std::string host;
        uint16_t port;
        std::vector<sockaddr_storage> addrs;  // Empty if resolution failed
    };

    explicit DnsResolver(int num_threads = 2);
    ~DnsResolver();

    DnsResolver(const DnsResolver&) = delete;
    DnsResolver& operator=(const DnsResolver&) = delete;

    // Register eventfd with reactor - must be called to set up signaling
    int get_eventfd() const { return eventfd_; }

    // Submit a DNS resolution task (non-blocking), returns job_id
    int64_t submit(const std::string& host, uint16_t port);

    // Drain all completed results from the results queue
    // Call this when eventfd becomes readable
    std::vector<Result> drain_results();

private:
    struct Job {
        int64_t id;
        std::string host;
        uint16_t port;
    };

    void worker_thread_main();

    int eventfd_;  // For waking up the reactor
    int64_t next_job_id_{1};

    // Job queue
    std::mutex job_mutex_;
    std::queue<Job> pending_jobs_;
    std::condition_variable job_cv_;

    // Results queue
    std::mutex result_mutex_;
    std::queue<Result> completed_results_;

    // Thread pool
    std::vector<std::thread> workers_;
    bool shutdown_{false};
};

}  // namespace proxy
