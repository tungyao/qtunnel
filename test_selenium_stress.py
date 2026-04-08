#!/usr/bin/env python3
"""
Selenium/Chrome stress test for qtunnel HTTP proxy.
Opens multiple Chrome instances/tabs simultaneously to stress test the proxy.
"""

import sys
import time
import subprocess
import os
import threading
import signal
from pathlib import Path
from datetime import datetime

# Install requirements if needed
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
except ImportError:
    print("[-] Selenium not available. Installing...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "selenium", "webdriver-manager"])
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

class StressTest:
    def __init__(self, proxy_url="http://127.0.0.1:11080", num_parallel=10):
        self.proxy_url = proxy_url
        self.num_parallel = num_parallel
        self.threads = []
        self.passed = 0
        self.failed = 0
        self.lock = threading.Lock()

        # Test URLs with different complexities
        self.test_urls = [
            "https://example.com/",
            "https://www.google.com/",
            "https://www.wikipedia.org/",
            "https://www.github.com/",
            "https://www.amazon.com/",
            "https://www.youtube.com/",
            "https://www.reddit.com/",
            "https://www.stackoverflow.com/",
            "https://www.facebook.com/",
            "https://www.twitter.com/",
            "https://www.linkedin.com/",
            "https://www.medium.com/",
        ]

    def create_chrome_options(self):
        """Create Chrome options with proxy and headless settings"""
        options = Options()
        options.headless = True
        options.add_argument("--start-maximized")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-extensions")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--disable-popup-blocking")

        # Configure proxy for HTTP and HTTPS
        proxy_url = self.proxy_url.replace("http://", "").replace("https://", "")
        options.add_argument(f"--proxy-server=http://{proxy_url}")

        # Disable logging
        options.add_argument("--log-level=3")

        return options

    def test_url(self, url, test_id):
        """Test a single URL in a separate thread"""
        try:
            print(f"[{test_id}] Opening: {url}")

            options = self.create_chrome_options()
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(30)

            try:
                start_time = time.time()
                driver.get(url)
                load_time = time.time() - start_time

                # Wait for page to load
                time.sleep(2)

                # Get page info
                title = driver.title
                page_size = len(driver.page_source)

                print(f"[{test_id}] ✓ {url} - Title: {title[:50]}, Size: {page_size} bytes, Time: {load_time:.2f}s")

                with self.lock:
                    self.passed += 1

            except Exception as e:
                print(f"[{test_id}] ✗ {url} - Error: {str(e)[:100]}")
                with self.lock:
                    self.failed += 1
            finally:
                driver.quit()

        except Exception as e:
            print(f"[{test_id}] ✗ Chrome launch error: {str(e)[:100]}")
            with self.lock:
                self.failed += 1

    def run_sequential_test(self):
        """Run URLs sequentially (one at a time)"""
        print(f"\n[*] Starting sequential test with {len(self.test_urls)} URLs")

        for i, url in enumerate(self.test_urls, 1):
            print(f"\n[Sequential {i}/{len(self.test_urls)}]")
            self.test_url(url, f"seq-{i}")
            time.sleep(1)  # Small delay between tests

    def run_parallel_test(self):
        """Run URLs in parallel (multiple Chrome instances)"""
        print(f"\n[*] Starting parallel test with {self.num_parallel} concurrent Chrome instances")
        print(f"[*] Testing {len(self.test_urls)} URLs")

        # Create more test jobs than parallel slots to stress test
        test_jobs = []
        for cycle in range(3):  # 3 cycles of testing
            for i, url in enumerate(self.test_urls, 1):
                test_jobs.append((url, f"par-c{cycle+1}-{i}"))

        # Run tests with limited concurrency
        active_threads = []
        for url, test_id in test_jobs:
            # Wait if too many threads are running
            while len([t for t in active_threads if t.is_alive()]) >= self.num_parallel:
                time.sleep(0.5)

            thread = threading.Thread(target=self.test_url, args=(url, test_id))
            thread.daemon = True
            thread.start()
            active_threads.append(thread)
            time.sleep(0.2)  # Small delay between starting threads

        # Wait for all threads to complete
        for thread in active_threads:
            thread.join()

    def monitor_server(self):
        """Monitor server process for crashes"""
        print("[*] Monitoring server for crashes...")
        while True:
            try:
                # Check if server is still running
                result = subprocess.run(["pgrep", "-f", "qtunnel_server"],
                                      capture_output=True)
                if result.returncode != 0:
                    print("[-] Server process died!")
                    return False
                time.sleep(1)
            except:
                break
        return True

def main():
    print(f"[*] qtunnel HTTP Proxy Stress Test")
    print(f"[*] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Create directories
    Path("test/logs").mkdir(exist_ok=True)

    # Start server with crash monitoring
    print("[*] Starting qtunnel server...")
    server_log = open("test/logs/server_stress.log", "w", buffering=1)
    server_proc = subprocess.Popen(
        ["./build/qtunnel_server",
         "--listen", "18443",
         "--cert-file", "test/certs/server.crt",
         "--key-file", "test/certs/server.key",
         "--log-level", "Info"],
        stdout=server_log,
        stderr=subprocess.STDOUT
    )

    # Start client
    print("[*] Starting qtunnel client...")
    client_log = open("test/logs/client_stress.log", "w", buffering=1)
    client_proc = subprocess.Popen(
        ["./build/qtunnel_client",
         "127.0.0.1:18443",
         "--listen", "11080",
         "--log-level", "info"],
        stdout=client_log,
        stderr=subprocess.STDOUT
    )

    time.sleep(3)

    # Check if processes started
    if not subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode == 0:
        print("[-] Server failed to start")
        return 1

    if not subprocess.run(["pgrep", "-f", "qtunnel_client"],
                         capture_output=True).returncode == 0:
        print("[-] Client failed to start")
        return 1

    try:
        # Create stress test
        stress = StressTest(proxy_url="http://127.0.0.1:11080", num_parallel=10)

        # Run tests
        print("\n" + "="*60)
        print("TEST 1: Sequential Test (baseline)")
        print("="*60)
        stress.run_sequential_test()

        print("\n" + "="*60)
        print("TEST 2: Parallel Test (stress)")
        print("="*60)
        stress.run_parallel_test()

        # Print results
        print("\n" + "="*60)
        print("TEST RESULTS")
        print("="*60)
        print(f"Total passed: {stress.passed}")
        print(f"Total failed: {stress.failed}")
        total = stress.passed + stress.failed
        if total > 0:
            success_rate = (stress.passed / total) * 100
            print(f"Success rate: {success_rate:.1f}%")

        # Check server logs for crashes
        server_log.close()
        client_log.close()

        with open("test/logs/server_stress.log", "r") as f:
            server_content = f.read()
            if "Segmentation fault" in server_content or "segfault" in server_content:
                print("[-] SEGMENTATION FAULT DETECTED IN SERVER LOG!")
                print(server_content[-500:])
                return 1

        # Check if processes are still alive
        if subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode != 0:
            print("[-] Server crashed during test!")
            return 1

        if stress.passed > 0 and stress.failed == 0:
            print("\n[+] All tests passed! Server is stable.")
            return 0
        else:
            print(f"\n[-] Some tests failed. Server may have issues.")
            return 1

    except KeyboardInterrupt:
        print("\n[-] Test interrupted by user")
        return 1
    except Exception as e:
        print(f"[-] Test error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        print("[*] Cleaning up...")
        server_proc.terminate()
        client_proc.terminate()
        time.sleep(1)
        server_proc.kill()
        client_proc.kill()
        server_log.close()
        client_log.close()

        print(f"[*] End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Print last lines of logs
        print("\n[*] Server log (last 20 lines):")
        try:
            with open("test/logs/server_stress.log", "r") as f:
                lines = f.readlines()
                for line in lines[-20:]:
                    print("  " + line.rstrip())
        except:
            pass

if __name__ == "__main__":
    sys.exit(main())
