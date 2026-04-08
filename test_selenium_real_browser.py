#!/usr/bin/env python3
"""
Real browser stress test with timing measurements.
Uses Selenium/Chrome to load real webpages through the HTTP proxy.
"""

import sys
import time
import subprocess
import threading
from datetime import datetime
from pathlib import Path
import re

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.by import By
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("Installing dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "selenium", "webdriver-manager"])
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager

class BrowserStressTest:
    def __init__(self, proxy_url="http://127.0.0.1:11080", num_parallel=5):
        self.proxy_url = proxy_url
        self.num_parallel = num_parallel
        self.results = []
        self.lock = threading.Lock()
        self.driver_count = 0

        # Real websites that require actual page loading
        self.test_pages = [
            "https://www.google.com/search?q=python",
            "https://www.github.com/",
            "https://www.example.com/",
        ]

    def create_chrome_options(self):
        """Create Chrome options optimized for headless container environments"""
        options = Options()

        # Headless mode
        options.add_argument("--headless=new")

        # Container/sandbox compatibility
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-setuid-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")

        # Proxy configuration
        proxy_address = self.proxy_url.replace("http://", "").replace("https://", "")
        options.add_argument(f"--proxy-server={proxy_address}")

        # Security and compatibility
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        options.add_argument("--allow-insecure-localhost")

        # Performance and stability
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--disable-plugins")
        options.add_argument("--disable-images")  # Disable images for speed
        options.add_argument("--disable-sync")

        # User agent
        options.add_argument("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

        return options

    def test_page(self, url, test_id):
        """Load a page and measure timing"""
        try:
            start_time = time.time()

            # Set up Chrome driver
            options = self.create_chrome_options()

            try:
                # Try with webdriver-manager first
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=options)
            except:
                # Fallback to system chromedriver
                driver = webdriver.Chrome(options=options)

            driver.set_page_load_timeout(30)
            driver.set_script_timeout(30)

            try:
                page_start = time.time()
                print(f"[{test_id}] Loading: {url}")

                driver.get(url)
                page_load_time = time.time() - page_start

                # Wait for page to be interactive
                time.sleep(1)

                # Get page metrics
                try:
                    title = driver.title
                except:
                    title = "N/A"

                try:
                    page_size = len(driver.page_source)
                except:
                    page_size = 0

                total_time = time.time() - start_time

                print(f"[{test_id}] ✓ SUCCESS: {url}")
                print(f"         Title: {title[:50]}")
                print(f"         Page load: {page_load_time:.2f}s, Total time: {total_time:.2f}s")
                print(f"         Page size: {page_size} bytes")

                with self.lock:
                    self.results.append({
                        'url': url,
                        'status': 'success',
                        'page_load_time': page_load_time,
                        'total_time': total_time,
                        'page_size': page_size,
                        'title': title
                    })

            except Exception as e:
                error_msg = str(e)[:100]
                print(f"[{test_id}] ✗ FAILED: {url}")
                print(f"         Error: {error_msg}")

                with self.lock:
                    self.results.append({
                        'url': url,
                        'status': 'failed',
                        'error': error_msg,
                        'total_time': time.time() - start_time
                    })
            finally:
                try:
                    driver.quit()
                except:
                    pass

        except Exception as e:
            print(f"[{test_id}] ✗ DRIVER ERROR: {str(e)[:100]}")
            with self.lock:
                self.results.append({
                    'url': url,
                    'status': 'error',
                    'error': str(e)[:100],
                    'total_time': 0
                })

    def run_test(self, cycles=3):
        """Run stress test with specified cycles"""
        print(f"\n{'='*70}")
        print(f"Browser Stress Test")
        print(f"{'='*70}")
        print(f"Proxy: {self.proxy_url}")
        print(f"Parallel browsers: {self.num_parallel}")
        print(f"Test cycles: {cycles}")
        print(f"Pages per cycle: {len(self.test_pages)}")
        print(f"{'='*70}\n")

        threads = []
        test_count = 0

        for cycle in range(1, cycles + 1):
            print(f"\n[CYCLE {cycle}/{cycles}]")

            for page_id, url in enumerate(self.test_pages, 1):
                test_count += 1
                test_id = f"C{cycle}-P{page_id}"

                # Wait if too many threads running
                while len([t for t in threads if t.is_alive()]) >= self.num_parallel:
                    time.sleep(0.1)

                thread = threading.Thread(
                    target=self.test_page,
                    args=(url, test_id)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)

                time.sleep(0.1)  # Small delay between starting threads

            # Wait for cycle to complete
            for thread in threads[-len(self.test_pages):]:
                thread.join()

            print(f"Cycle {cycle} complete")
            time.sleep(1)

        # Wait for all threads
        for thread in threads:
            thread.join()

        return self.print_results()

    def print_results(self):
        """Print test results and statistics"""
        print(f"\n{'='*70}")
        print(f"Test Results")
        print(f"{'='*70}")

        successful = [r for r in self.results if r['status'] == 'success']
        failed = [r for r in self.results if r['status'] != 'success']

        print(f"\nTotal tests: {len(self.results)}")
        print(f"Successful: {len(successful)}")
        print(f"Failed: {len(failed)}")

        if len(self.results) > 0:
            success_rate = (len(successful) / len(self.results)) * 100
            print(f"Success rate: {success_rate:.1f}%")

        if successful:
            print(f"\n{'─'*70}")
            print("Timing Statistics (successful requests):")
            print(f"{'─'*70}")

            load_times = [r['page_load_time'] for r in successful]
            total_times = [r['total_time'] for r in successful]

            if load_times:
                avg_load = sum(load_times) / len(load_times)
                min_load = min(load_times)
                max_load = max(load_times)
                print(f"Page Load Time: avg={avg_load:.2f}s, min={min_load:.2f}s, max={max_load:.2f}s")

            if total_times:
                avg_total = sum(total_times) / len(total_times)
                min_total = min(total_times)
                max_total = max(total_times)
                print(f"Total Time:     avg={avg_total:.2f}s, min={min_total:.2f}s, max={max_total:.2f}s")

        if failed:
            print(f"\n{'─'*70}")
            print("Failed requests:")
            print(f"{'─'*70}")
            for r in failed:
                print(f"  {r['url']}: {r.get('error', 'Unknown error')}")

        print(f"\n{'='*70}\n")

        return len(failed) == 0

def main():
    # Setup
    Path("test/logs").mkdir(exist_ok=True)

    server_log = open("test/logs/browser_stress_server.log", "w", buffering=1)
    client_log = open("test/logs/browser_stress_client.log", "w", buffering=1)

    try:
        # Start server
        print("[*] Starting qtunnel server...")
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
        client_proc = subprocess.Popen(
            ["./build/qtunnel_client",
             "127.0.0.1:18443",
             "--listen", "11080",
             "--log-level", "info"],
            stdout=client_log,
            stderr=subprocess.STDOUT
        )

        time.sleep(3)

        # Verify
        if subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode != 0:
            print("[-] Server failed to start")
            return 1

        if subprocess.run(["pgrep", "-f", "qtunnel_client"],
                         capture_output=True).returncode != 0:
            print("[-] Client failed to start")
            return 1

        # Run test
        tester = BrowserStressTest(
            proxy_url="http://127.0.0.1:11080",
            num_parallel=5
        )

        success = tester.run_test(cycles=3)

        # Check server logs
        server_log.close()
        client_log.close()

        with open("test/logs/browser_stress_server.log", "r") as f:
            server_content = f.read()
            if "Segmentation fault" in server_content or "segfault" in server_content:
                print("[!] SEGMENTATION FAULT DETECTED IN SERVER LOG!")
                return 1

        # Check if server crashed
        if subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode != 0:
            print("[!] Server crashed!")
            return 1

        if success:
            print("[✓] Browser stress test PASSED - Server is stable!")
            return 0
        else:
            print("[✗] Browser stress test had failures")
            return 1

    except KeyboardInterrupt:
        print("\n[!] Test interrupted")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        print("[*] Cleaning up...")
        server_proc.terminate()
        client_proc.terminate()
        time.sleep(1)
        subprocess.run(["pkill", "-9", "-f", "qtunnel_server"], stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "-f", "qtunnel_client"], stderr=subprocess.DEVNULL)
        server_log.close()
        client_log.close()

if __name__ == "__main__":
    sys.exit(main())
