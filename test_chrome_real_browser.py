#!/usr/bin/env python3
"""
Real Chrome browser stress test for qtunnel.
Uses actual Chrome/Chromium with Selenium to simulate real browser behavior.
"""

import sys
import time
import subprocess
import os
import signal
from pathlib import Path
from datetime import datetime
import threading
import traceback

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
except ImportError:
    print("Installing Selenium...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "selenium"])
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

class ChromeBrowserTest:
    def __init__(self, proxy_url="http://127.0.0.1:11080", num_browsers=5):
        self.proxy_url = proxy_url
        self.num_browsers = num_browsers
        self.results = []
        self.errors = []
        self.lock = threading.Lock()

        # Real test URLs that load heavy content
        self.urls = [
            "https://www.google.com/",
            "https://www.github.com/",
            "https://www.wikipedia.org/",
        ]

    def find_chrome_binary(self):
        """Find Chrome/Chromium binary"""
        candidates = [
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/snap/bin/chromium",
        ]

        for binary in candidates:
            if os.path.exists(binary):
                print(f"[*] Found Chrome binary: {binary}")
                return binary

        raise RuntimeError("Chrome/Chromium not found. Install with: apt install chromium-browser")

    def create_chrome_options(self):
        """Create Chrome options for headless testing"""
        options = Options()

        # Headless mode - use new headless implementation
        options.add_argument("--headless=new")

        # Container/sandbox fixes
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-setuid-sandbox")
        options.add_argument("--disable-dev-shm-usage")  # Use RAM instead of /dev/shm

        # Proxy configuration - critical for testing
        proxy_host = self.proxy_url.replace("http://", "").replace("https://", "")
        options.add_argument(f"--proxy-server={proxy_host}")

        # Security/SSL
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        options.add_argument("--allow-insecure-localhost")
        options.add_argument("--disable-blink-features=AutomationControlled")

        # Performance
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-sync")
        options.add_argument("--disable-web-resources")
        options.add_argument("--disable-default-apps")

        # Window size
        options.add_argument("--window-size=1920,1080")

        # User agent
        options.add_argument("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

        # Disable various features that might interfere
        options.add_argument("--disable-plugins")
        options.add_argument("--disable-pepper-3d-image-chromium")
        options.add_argument("--disable-renderer-backgrounding")
        options.add_argument("--disable-backgrounding-occluded-windows")

        return options

    def open_page(self, driver, url, browser_id):
        """Open a single page in the browser"""
        try:
            print(f"[Browser {browser_id}] Loading: {url}")
            start_time = time.time()

            driver.get(url)
            load_time = time.time() - start_time

            # Wait for page to be interactive
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_all_elements_located((By.TAG_NAME, "body"))
                )
            except TimeoutException:
                pass

            # Get page info
            title = driver.title
            page_size = len(driver.page_source)

            print(f"[Browser {browser_id}] ✓ {url}")
            print(f"              Title: {title[:50]}, Size: {page_size} bytes, Time: {load_time:.2f}s")

            with self.lock:
                self.results.append({
                    'url': url,
                    'status': 'success',
                    'title': title,
                    'time': load_time,
                    'size': page_size,
                    'browser_id': browser_id
                })

        except Exception as e:
            error_msg = str(e)[:100]
            print(f"[Browser {browser_id}] ✗ {url} - {error_msg}")
            with self.lock:
                self.results.append({
                    'url': url,
                    'status': 'failed',
                    'error': error_msg,
                    'browser_id': browser_id
                })
                self.errors.append(error_msg)

    def browser_session(self, browser_id, num_pages):
        """Run a browser session that loads multiple pages"""
        try:
            print(f"[Browser {browser_id}] Starting Chrome instance...")
            chrome_binary = self.find_chrome_binary()

            options = self.create_chrome_options()
            options.binary_location = chrome_binary

            # Create service
            service = Service()

            # Launch Chrome
            driver = webdriver.Chrome(
                service=service,
                options=options
            )

            print(f"[Browser {browser_id}] Chrome launched successfully")
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(10)

            try:
                # Load pages in sequence
                for i in range(num_pages):
                    url = self.urls[i % len(self.urls)]
                    self.open_page(driver, url, browser_id)
                    time.sleep(1)  # Small delay between page loads

            finally:
                print(f"[Browser {browser_id}] Closing Chrome...")
                driver.quit()

        except WebDriverException as e:
            error = f"Browser {browser_id} WebDriver error: {str(e)[:80]}"
            print(f"[Browser {browser_id}] ✗ {error}")
            with self.lock:
                self.errors.append(error)
        except Exception as e:
            error = f"Browser {browser_id} error: {str(e)[:80]}"
            print(f"[Browser {browser_id}] ✗ {error}")
            traceback.print_exc()
            with self.lock:
                self.errors.append(error)

    def run_test(self, num_pages_per_browser=5):
        """Run test with multiple Chrome instances"""
        print(f"\n{'='*70}")
        print(f"Real Chrome Browser Stress Test")
        print(f"{'='*70}")
        print(f"Proxy: {self.proxy_url}")
        print(f"Number of Chrome instances: {self.num_browsers}")
        print(f"Pages per browser: {num_pages_per_browser}")
        print(f"Total pages to load: {self.num_browsers * num_pages_per_browser}")
        print(f"{'='*70}\n")

        threads = []

        # Launch multiple Chrome instances in parallel
        for browser_id in range(1, self.num_browsers + 1):
            thread = threading.Thread(
                target=self.browser_session,
                args=(browser_id, num_pages_per_browser)
            )
            thread.daemon = False
            thread.start()
            threads.append(thread)
            time.sleep(2)  # Stagger Chrome launches

        # Wait for all to complete
        print("\n[*] Waiting for all browsers to complete...")
        for thread in threads:
            thread.join()

        return self.print_results()

    def print_results(self):
        """Print results"""
        print(f"\n{'='*70}")
        print(f"Test Results")
        print(f"{'='*70}\n")

        total = len(self.results)
        successful = [r for r in self.results if r['status'] == 'success']
        failed = [r for r in self.results if r['status'] != 'success']

        print(f"Total page loads:  {total}")
        print(f"Successful:        {len(successful)}")
        print(f"Failed:            {len(failed)}")

        if total > 0:
            success_rate = (len(successful) / total) * 100
            print(f"Success rate:      {success_rate:.1f}%")

        if successful:
            times = [r['time'] for r in successful]
            print(f"\nTiming (seconds):")
            print(f"  Average:  {sum(times) / len(times):.2f}s")
            print(f"  Min:      {min(times):.2f}s")
            print(f"  Max:      {max(times):.2f}s")

        if self.errors:
            print(f"\nErrors encountered:")
            for error in self.errors[:5]:  # Show first 5
                print(f"  - {error}")

        print(f"\n{'='*70}\n")

        return len(failed) == 0

def main():
    # Setup
    Path("test/logs").mkdir(exist_ok=True)

    print("[*] Starting qtunnel server...")
    server_proc = subprocess.Popen(
        ["./build/qtunnel_server",
         "--listen", "18443",
         "--cert-file", "test/certs/server.crt",
         "--key-file", "test/certs/server.key",
         "--log-level", "Info"],
        stdout=open("test/logs/chrome_stress_server.log", "w"),
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid
    )

    print("[*] Starting qtunnel client...")
    client_proc = subprocess.Popen(
        ["./build/qtunnel_client",
         "127.0.0.1:18443",
         "--listen", "11080",
         "--log-level", "info"],
        stdout=open("test/logs/chrome_stress_client.log", "w"),
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid
    )

    time.sleep(3)

    try:
        # Verify
        if subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode != 0:
            print("[-] Server failed to start")
            return 1

        if subprocess.run(["pgrep", "-f", "qtunnel_client"],
                         capture_output=True).returncode != 0:
            print("[-] Client failed to start")
            return 1

        # Run Chrome test
        tester = ChromeBrowserTest(
            proxy_url="http://127.0.0.1:11080",
            num_browsers=5
        )
        success = tester.run_test(num_pages_per_browser=5)

        # Check for crashes
        print("[*] Checking for server crashes...")
        with open("test/logs/chrome_stress_server.log", "r") as f:
            server_log = f.read()
            if "Segmentation fault" in server_log or "segfault" in server_log:
                print("[!] SEGMENTATION FAULT DETECTED IN SERVER LOG!")
                # Show the relevant part
                for line in server_log.split('\n'):
                    if 'segfault' in line.lower() or 'segmentation' in line.lower():
                        print(f"    {line}")
                return 1

        if subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode != 0:
            print("[!] Server crashed!")
            return 1

        print("[✓] Server is stable")

        if success:
            print("[✓] Chrome stress test PASSED")
            return 0
        else:
            print("[!] Some page loads failed - may indicate server issues")
            return 1

    except KeyboardInterrupt:
        print("\n[!] Test interrupted")
        return 1
    except Exception as e:
        print(f"[!] Error: {e}")
        traceback.print_exc()
        return 1
    finally:
        print("[*] Cleaning up...")
        try:
            os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
            os.killpg(os.getpgid(client_proc.pid), signal.SIGTERM)
        except:
            pass
        time.sleep(1)
        subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    sys.exit(main())
