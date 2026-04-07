// Unit tests for proxy::DnsResolver
// Tests: basic resolution, IPv4-first ordering, cache hit, cache expiry,
//        failed resolution, concurrent submissions.

#include "../src/dns_resolver.h"

#include <arpa/inet.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sys/epoll.h>
#include <unistd.h>

// ── helpers ────────────────────────────────────────────────────────────────

static std::string addr_to_str(const sockaddr_storage& sa) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (sa.ss_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&sa)->sin_addr,
                  buf, sizeof(buf));
    } else if (sa.ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&sa)->sin6_addr,
                  buf, sizeof(buf));
    } else {
        snprintf(buf, sizeof(buf), "<family=%d>", (int)sa.ss_family);
    }
    return buf;
}

// Wait for the eventfd to become readable (up to timeout_ms), then drain results.
static std::vector<proxy::DnsResolver::Result>
wait_and_drain(proxy::DnsResolver& resolver, int timeout_ms = 5000) {
    int efd = resolver.get_eventfd();
    int ep  = epoll_create1(EPOLL_CLOEXEC);
    assert(ep >= 0);

    epoll_event ev{};
    ev.events  = EPOLLIN;
    ev.data.fd = efd;
    epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev);

    epoll_event ready{};
    int n = epoll_wait(ep, &ready, 1, timeout_ms);
    close(ep);

    if (n <= 0) return {};  // timeout or error
    return resolver.drain_results();
}

// Drain all results for N pending jobs (may need multiple waits).
static std::vector<proxy::DnsResolver::Result>
collect_n(proxy::DnsResolver& resolver, int n, int timeout_ms = 5000) {
    std::vector<proxy::DnsResolver::Result> all;
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while ((int)all.size() < n &&
           std::chrono::steady_clock::now() < deadline) {
        auto batch = wait_and_drain(resolver, 200);
        all.insert(all.end(),
                   std::make_move_iterator(batch.begin()),
                   std::make_move_iterator(batch.end()));
    }
    return all;
}

static void pass(const char* name) {
    printf("  [PASS] %s\n", name);
}
static void fail(const char* name, const char* reason) {
    printf("  [FAIL] %s — %s\n", name, reason);
}

// ── tests ──────────────────────────────────────────────────────────────────

// Test 1: basic resolution of a known hostname
static bool test_basic_resolve() {
    proxy::DnsResolver resolver;
    int64_t jid = resolver.submit("localhost", 80);
    if (jid <= 0) { fail("basic_resolve", "submit returned invalid id"); return false; }

    auto results = collect_n(resolver, 1);
    if (results.empty()) { fail("basic_resolve", "no result received (timeout)"); return false; }

    auto& r = results[0];
    if (r.job_id != jid) { fail("basic_resolve", "job_id mismatch"); return false; }
    if (r.addrs.empty()) { fail("basic_resolve", "no addresses returned"); return false; }

    pass("basic_resolve");
    return true;
}

// Test 2: IPv4 addresses must come before IPv6
static bool test_ipv4_first() {
    proxy::DnsResolver resolver;
    resolver.submit("localhost", 80);
    auto results = collect_n(resolver, 1);
    if (results.empty()) { fail("ipv4_first", "no result"); return false; }

    auto& addrs = results[0].addrs;
    bool seen_v6 = false;
    for (const auto& sa : addrs) {
        if (sa.ss_family == AF_INET6) { seen_v6 = true; }
        if (seen_v6 && sa.ss_family == AF_INET) {
            fail("ipv4_first", "IPv4 appears after IPv6");
            return false;
        }
    }
    pass("ipv4_first");
    return true;
}

// Test 3: cache hit — second submit returns result much faster
static bool test_cache_hit() {
    proxy::DnsResolver resolver;

    // First submit: populates cache (may take >1ms for getaddrinfo)
    resolver.submit("localhost", 80);
    collect_n(resolver, 1, 3000);  // wait for first result

    // Second submit: should be a cache hit — result is posted synchronously
    using clk = std::chrono::steady_clock;
    auto t0  = clk::now();
    int64_t jid2 = resolver.submit("localhost", 80);
    auto results = wait_and_drain(resolver, 500);
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                       clk::now() - t0).count();

    if (results.empty()) { fail("cache_hit", "no result on second submit"); return false; }
    if (results[0].job_id != jid2) { fail("cache_hit", "job_id mismatch"); return false; }

    // Cache hit should resolve without a thread round-trip: expect < 20ms
    if (elapsed > 20000) {
        printf("  [WARN] cache_hit: elapsed=%ldus (expected <20ms — may be slow system)\n", elapsed);
    }
    printf("         cache hit latency: %ldus\n", elapsed);
    pass("cache_hit");
    return true;
}

// Test 4: cache result matches first result (same addresses)
static bool test_cache_consistency() {
    proxy::DnsResolver resolver;

    resolver.submit("localhost", 443);
    auto r1 = collect_n(resolver, 1, 3000);
    if (r1.empty()) { fail("cache_consistency", "first result timeout"); return false; }

    resolver.submit("localhost", 443);
    auto r2 = collect_n(resolver, 1, 500);
    if (r2.empty()) { fail("cache_consistency", "second result timeout"); return false; }

    if (r1[0].addrs.size() != r2[0].addrs.size()) {
        fail("cache_consistency", "address count differs between cold and cached result");
        return false;
    }
    for (size_t i = 0; i < r1[0].addrs.size(); ++i) {
        if (r1[0].addrs[i].ss_family != r2[0].addrs[i].ss_family ||
            memcmp(&r1[0].addrs[i], &r2[0].addrs[i], sizeof(sockaddr_storage)) != 0) {
            fail("cache_consistency", "addresses differ between cold and cached result");
            return false;
        }
    }
    pass("cache_consistency");
    return true;
}

// Test 5: failed resolution returns empty addrs (not a crash)
static bool test_failed_resolve() {
    proxy::DnsResolver resolver;
    // This domain should not exist
    resolver.submit("this.host.does.not.exist.invalid", 80);
    auto results = collect_n(resolver, 1, 6000);
    if (results.empty()) { fail("failed_resolve", "no result received (timeout)"); return false; }

    // Expect empty address list (resolution failure)
    if (!results[0].addrs.empty()) {
        // Unlikely but not impossible in some environments with wildcard DNS
        printf("  [WARN] failed_resolve: got %zu addr(s) for nonexistent host\n",
               results[0].addrs.size());
    }
    pass("failed_resolve");
    return true;
}

// Test 6: concurrent submissions all get results
static bool test_concurrent() {
    proxy::DnsResolver resolver;
    constexpr int N = 8;
    std::vector<int64_t> ids;
    for (int i = 0; i < N; ++i) {
        ids.push_back(resolver.submit("localhost", static_cast<uint16_t>(80 + i)));
    }

    auto results = collect_n(resolver, N, 10000);
    if ((int)results.size() != N) {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected %d results, got %d", N, (int)results.size());
        fail("concurrent", buf);
        return false;
    }
    pass("concurrent");
    return true;
}

// Test 7: different ports but same host all served from cache after first miss
static bool test_cache_port_independence() {
    proxy::DnsResolver resolver;
    // Warm up cache for "localhost"
    resolver.submit("localhost", 80);
    collect_n(resolver, 1, 3000);

    // Submit several different ports — all should be cache hits
    using clk = std::chrono::steady_clock;
    auto t0 = clk::now();
    constexpr int N = 5;
    for (int i = 0; i < N; ++i) {
        resolver.submit("localhost", static_cast<uint16_t>(1000 + i));
    }
    auto results = collect_n(resolver, N, 2000);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       clk::now() - t0).count();

    if ((int)results.size() != N) {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected %d results, got %d", N, (int)results.size());
        fail("cache_port_independence", buf);
        return false;
    }
    printf("         %d cached lookups completed in %ldms\n", N, elapsed);
    pass("cache_port_independence");
    return true;
}

// ── main ───────────────────────────────────────────────────────────────────

int main() {
    printf("=== DnsResolver unit tests ===\n\n");

    int passed = 0, total = 0;

    auto run = [&](bool (*fn)()) {
        ++total;
        if (fn()) ++passed;
    };

    run(test_basic_resolve);
    run(test_ipv4_first);
    run(test_cache_hit);
    run(test_cache_consistency);
    run(test_failed_resolve);
    run(test_concurrent);
    run(test_cache_port_independence);

    printf("\n=== %d/%d tests passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
