#!/usr/bin/env python3
"""
Headless browser test for qtunnel HTTP proxy.
Tests the proxy with Selenium/Playwright to simulate real browser usage.
"""

import sys
import time
import subprocess
import os
import signal
from pathlib import Path

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("Playwright not available, trying Selenium...")

# Try to import Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

def test_with_playwright(proxy_url, test_url="https://example.com/"):
    """Test using Playwright"""
    print(f"[*] Testing with Playwright: {test_url}")

    if not PLAYWRIGHT_AVAILABLE:
        print("[-] Playwright not available")
        return False

    with sync_playwright() as p:
        # Launch browser with HTTP proxy
        browser = p.chromium.launch(
            headless=True,
            args=[
                f"--proxy-server={proxy_url}",
            ]
        )

        context = browser.new_context()
        page = context.new_page()

        try:
            page.goto(test_url, timeout=30000)
            print(f"[+] Page loaded successfully: {page.title()}")

            # Take a screenshot
            page.screenshot(path="/tmp/qtunnel_test.png")
            print("[+] Screenshot saved to /tmp/qtunnel_test.png")

            # Check page content
            content = page.content()
            if len(content) > 100:
                print(f"[+] Page content received: {len(content)} bytes")

            context.close()
            browser.close()
            return True
        except Exception as e:
            print(f"[-] Error: {e}")
            context.close()
            browser.close()
            return False

def test_with_selenium(proxy_url, test_url="https://example.com/"):
    """Test using Selenium with Chrome"""
    print(f"[*] Testing with Selenium: {test_url}")

    if not SELENIUM_AVAILABLE:
        print("[-] Selenium not available")
        return False

    try:
        options = Options()
        options.headless = True

        # Configure HTTP proxy
        # Note: For HTTPS, we need to handle certificates
        proxy_option = f"http://{proxy_url.replace('http://', '')}"

        # Create proxy capabilities
        from selenium.webdriver.common.proxy import Proxy, ProxyType
        proxy = Proxy()
        proxy.proxy_type = ProxyType.MANUAL
        proxy.http_proxy = proxy_option
        proxy.https_proxy = proxy_option

        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)

        try:
            driver.get(test_url)
            print(f"[+] Page title: {driver.title}")

            # Wait for page to load
            time.sleep(2)

            # Take screenshot
            driver.save_screenshot("/tmp/qtunnel_test_selenium.png")
            print("[+] Screenshot saved to /tmp/qtunnel_test_selenium.png")

            page_source = driver.page_source
            if len(page_source) > 100:
                print(f"[+] Page content received: {len(page_source)} bytes")

            driver.quit()
            return True
        except Exception as e:
            print(f"[-] Error: {e}")
            driver.quit()
            return False
    except Exception as e:
        print(f"[-] Setup error: {e}")
        return False

def test_with_curl(proxy_url, test_url="https://example.com/"):
    """Test using curl as fallback"""
    print(f"[*] Testing with curl: {test_url}")

    try:
        result = subprocess.run(
            ["curl", "-x", proxy_url, "-v", test_url],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:
            print(f"[+] Request successful")
            print(f"[+] Response length: {len(result.stdout)} bytes")
            return True
        else:
            print(f"[-] Request failed with code {result.returncode}")
            if result.stderr:
                print(f"[-] Error: {result.stderr[:500]}")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    # Start server
    print("[*] Starting qtunnel server...")
    server_proc = subprocess.Popen(
        ["./build/qtunnel_server",
         "--listen", "18443",
         "--cert-file", "test/certs/server.crt",
         "--key-file", "test/certs/server.key",
         "--log-level", "Info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Start client
    print("[*] Starting qtunnel client...")
    client_proc = subprocess.Popen(
        ["./build/qtunnel_client",
         "127.0.0.1:18443",
         "--listen", "11080",
         "--log-level", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(3)

    try:
        # Test URLs
        test_urls = [
            "https://example.com/",
            "https://www.google.com/",
        ]

        proxy_url = "http://127.0.0.1:11080"
        all_passed = True

        for test_url in test_urls:
            print(f"\n[*] Testing {test_url}")

            # Try different test methods
            if PLAYWRIGHT_AVAILABLE:
                passed = test_with_playwright(proxy_url, test_url)
                if passed:
                    print(f"[+] {test_url} passed with Playwright")
                    continue

            if SELENIUM_AVAILABLE:
                passed = test_with_selenium(proxy_url, test_url)
                if passed:
                    print(f"[+] {test_url} passed with Selenium")
                    continue

            # Fallback to curl
            passed = test_with_curl(proxy_url, test_url)
            if passed:
                print(f"[+] {test_url} passed with curl")
            else:
                print(f"[-] {test_url} failed")
                all_passed = False

        if all_passed:
            print("\n[+] All tests passed!")
            return 0
        else:
            print("\n[-] Some tests failed")
            return 1

    finally:
        print("[*] Cleaning up...")
        server_proc.terminate()
        client_proc.terminate()
        time.sleep(1)
        server_proc.kill()
        client_proc.kill()

if __name__ == "__main__":
    sys.exit(main())
