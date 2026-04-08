#!/usr/bin/env python3
"""
Stress test for qtunnel with timing analysis.
Concurrent requests through HTTP proxy with response time tracking.
"""

import sys
import time
import subprocess
import threading
import statistics
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError
import ssl

class LoadTest:
    def __init__(self, proxy_host="127.0.0.1", proxy_port=11080, num_workers=15):
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
        self.num_workers = num_workers
        self.results = []
        self.lock = threading.Lock()

        # Real test URLs
        self.urls = [
            "https://www.google.com/",
            "https://www.github.com/",
            "https://www.wikipedia.org/",
            "https://www.example.com/",
        ]

    def test_url(self, url, test_id):
        """Test single URL and record timing"""
        try:
            # Setup proxy for urllib
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({
                'http': self.proxy_url,
                'https': self.proxy_url
            })

            # Disable SSL verification for this test
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

            # Measure request time
            start = time.time()
            try:
                response = urlopen(url, timeout=20, context=ssl_context)
                response_time = time.time() - start
                status_code = response.status
                content_size = len(response.read())
                response.close()

                status = 'success'
                print(f"[{test_id}] ✓ {url} ({status_code}) - {response_time:.3f}s, {content_size} bytes")

            except URLError as e:
                response_time = time.time() - start
                status = 'failed'
                status_code = 0
                print(f"[{test_id}] ✗ {url} - Error: {str(e)[:50]}")

            with self.lock:
                self.results.append({
                    'url': url,
                    'status': status,
                    'time': response_time,
                    'code': status_code,
                    'timestamp': datetime.now()
                })

        except Exception as e:
            print(f"[{test_id}] ✗ {url} - Exception: {str(e)[:50]}")
            with self.lock:
                self.results.append({
                    'url': url,
                    'status': 'error',
                    'time': 0,
                    'code': 0,
                    'error': str(e)
                })

    def run_test(self, duration_seconds=300, cycles=None):
        """Run load test for specified duration"""
        print(f"\n{'='*70}")
        print(f"qtunnel HTTP Proxy Load Test")
        print(f"{'='*70}")
        print(f"Proxy: {self.proxy_url}")
        print(f"Concurrent workers: {self.num_workers}")
        print(f"Test URLs: {len(self.urls)}")
        print(f"Test duration: {duration_seconds}s")
        print(f"{'='*70}\n")

        threads = []
        test_count = 0
        start_time = time.time()

        while (time.time() - start_time) < duration_seconds:
            # Submit test jobs
            for url in self.urls:
                test_count += 1
                test_id = f"Test-{test_count}"

                # Wait if too many threads
                while len([t for t in threads if t.is_alive()]) >= self.num_workers:
                    time.sleep(0.01)

                thread = threading.Thread(target=self.test_url, args=(url, test_id))
                thread.daemon = True
                thread.start()
                threads.append(thread)

                elapsed = time.time() - start_time
                if elapsed >= duration_seconds:
                    break

            # Print progress
            elapsed = time.time() - start_time
            percent = int((elapsed / duration_seconds) * 100)
            print(f"Progress: {percent}% ({int(elapsed)}s / {duration_seconds}s) - {test_count} tests submitted")

            time.sleep(1)

        # Wait for remaining threads
        print("Waiting for remaining requests to complete...")
        for thread in threads:
            thread.join()

        return self.print_results()

    def print_results(self):
        """Print statistics"""
        print(f"\n{'='*70}")
        print(f"Results")
        print(f"{'='*70}\n")

        total = len(self.results)
        successful = [r for r in self.results if r['status'] == 'success']
        failed = [r for r in self.results if r['status'] != 'success']

        print(f"Total requests:    {total}")
        print(f"Successful:        {len(successful)}")
        print(f"Failed:            {len(failed)}")

        if total > 0:
            success_rate = (len(successful) / total) * 100
            print(f"Success rate:      {success_rate:.1f}%")

        # Timing statistics
        if successful:
            times = [r['time'] for r in successful]
            print(f"\nTiming Statistics (seconds):")
            print(f"  Average:         {statistics.mean(times):.3f}s")
            print(f"  Median:          {statistics.median(times):.3f}s")
            print(f"  Minimum:         {min(times):.3f}s")
            print(f"  Maximum:         {max(times):.3f}s")
            if len(times) > 1:
                print(f"  Std Dev:         {statistics.stdev(times):.3f}s")

        # Per-URL statistics
        if successful:
            print(f"\nPer-URL Statistics:")
            by_url = {}
            for r in successful:
                url = r['url']
                if url not in by_url:
                    by_url[url] = []
                by_url[url].append(r['time'])

            for url, times in sorted(by_url.items()):
                avg = statistics.mean(times)
                count = len(times)
                print(f"  {url}: {count} requests, avg {avg:.3f}s")

        print(f"\n{'='*70}\n")

        return len(failed) == 0

def main():
    # Setup
    import os
    os.makedirs("test/logs", exist_ok=True)

    print("[*] Starting qtunnel server...")
    server_proc = subprocess.Popen(
        ["./build/qtunnel_server",
         "--listen", "18443",
         "--cert-file", "test/certs/server.crt",
         "--key-file", "test/certs/server.key",
         "--log-level", "Info"],
        stdout=open("test/logs/stress_server.log", "w"),
        stderr=subprocess.STDOUT
    )

    print("[*] Starting qtunnel client...")
    client_proc = subprocess.Popen(
        ["./build/qtunnel_client",
         "127.0.0.1:18443",
         "--listen", "11080",
         "--log-level", "info"],
        stdout=open("test/logs/stress_client.log", "w"),
        stderr=subprocess.STDOUT
    )

    time.sleep(3)

    # Verify
    try:
        if subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode != 0:
            print("[-] Server failed to start")
            return 1

        if subprocess.run(["pgrep", "-f", "qtunnel_client"],
                         capture_output=True).returncode != 0:
            print("[-] Client failed to start")
            return 1

        # Run test
        tester = LoadTest(num_workers=15)
        success = tester.run_test(duration_seconds=300)  # 5 minutes

        # Check for crashes
        with open("test/logs/stress_server.log", "r") as f:
            if "Segmentation fault" in f.read():
                print("[!] SEGMENTATION FAULT DETECTED")
                return 1

        if subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode != 0:
            print("[!] Server crashed")
            return 1

        if success:
            print("[✓] STRESS TEST PASSED - Server stable!")
            return 0
        else:
            print("[✗] Some requests failed")
            return 1

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 1
    finally:
        server_proc.terminate()
        client_proc.terminate()
        time.sleep(1)
        subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    sys.exit(main())
