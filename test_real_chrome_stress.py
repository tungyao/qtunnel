#!/usr/bin/env python3
"""
Real Chrome browser stress test using Playwright.
Opens real Chrome instances and loads actual webpages through the proxy.
"""

import sys
import time
import subprocess
import os
import signal
from pathlib import Path
from datetime import datetime
import threading
from multiprocessing import Pool, Process

def install_dependencies():
    """Install Playwright and browsers"""
    try:
        from playwright.sync_api import sync_playwright
        return True
    except ImportError:
        print("[*] Installing Playwright...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "playwright"])
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"])
        return True

def load_page_with_chrome(browser_id, url, proxy_url):
    """Load a single page with real Chrome through proxy"""
    try:
        from playwright.sync_api import sync_playwright, BrowserContext
        import json

        start_time = time.time()

        with sync_playwright() as p:
            # Launch real Chrome with proxy
            browser = p.chromium.launch(
                headless=True,
                proxy={
                    "server": proxy_url,
                    "bypass": "localhost"
                },
                args=[
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                ]
            )

            context = browser.new_context(
                ignore_https_errors=True,
            )
            page = context.new_page()

            try:
                # Set timeout
                page.set_default_timeout(3000)

                # Load the page
                page_start = time.time()
                response = page.goto(url, wait_until="domcontentloaded")
                page_load_time = time.time() - page_start

                # Get page info
                title = page.title()
                content_size = len(page.content())
                status_code = response.status if response else 0

                total_time = time.time() - start_time

                print(f"[Browser {browser_id}] ✓ {url}")
                print(f"              Status: {status_code}, Title: {title[:40]}, Time: {total_time:.2f}s")

                context.close()
                browser.close()

                return {
                    'browser_id': browser_id,
                    'url': url,
                    'status': 'success',
                    'title': title,
                    'status_code': status_code,
                    'page_load_time': page_load_time,
                    'total_time': total_time,
                    'content_size': content_size
                }

            except Exception as e:
                error_msg = str(e)[:100]
                print(f"[Browser {browser_id}] ✗ {url} - {error_msg}")

                try:
                    context.close()
                    browser.close()
                except:
                    pass

                return {
                    'browser_id': browser_id,
                    'url': url,
                    'status': 'failed',
                    'error': error_msg,
                    'total_time': time.time() - start_time
                }

    except Exception as e:
        print(f"[Browser {browser_id}] ✗ Error: {str(e)[:80]}")
        return {
            'browser_id': browser_id,
            'url': url,
            'status': 'error',
            'error': str(e)[:80],
            'total_time': 0
        }

def run_chrome_browser_test(num_browsers=5, pages_per_browser=5, proxy_url="http://127.0.0.1:11080"):
    """Run real Chrome browser test"""

    print(f"\n{'='*70}")
    print(f"Real Chrome Browser Stress Test")
    print(f"{'='*70}")
    print(f"Proxy: {proxy_url}")
    print(f"Number of Chrome instances: {num_browsers}")
    print(f"Pages per instance: {pages_per_browser}")
    print(f"Total pages: {num_browsers * pages_per_browser}")
    print(f"{'='*70}\n")

    # Test URLs
    urls = [
        "https://www.google.com/",
        "https://www.github.com/",
	"https://www.baidu.com/",
	"https://www.bilibili.com/",
    ]

    # Create tasks
    tasks = []
    for browser_id in range(1, num_browsers + 1):
        for page_idx in range(pages_per_browser):
            url = urls[page_idx % len(urls)]
            tasks.append((browser_id, url, proxy_url))

    # Run with process pool
    print("[*] Launching Chrome instances...")
    results = []

    with Pool(processes=num_browsers) as pool:
        results = pool.starmap(load_page_with_chrome, tasks)

    # Print results
    print(f"\n{'='*70}")
    print(f"Results")
    print(f"{'='*70}\n")

    successful = [r for r in results if r['status'] == 'success']
    failed = [r for r in results if r['status'] != 'success']

    print(f"Total pages loaded: {len(results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")

    if len(results) > 0:
        success_rate = (len(successful) / len(results)) * 100
        print(f"Success rate: {success_rate:.1f}%")

    if successful:
        times = [r['total_time'] for r in successful]
        print(f"\nTiming Statistics (seconds):")
        print(f"  Average: {sum(times) / len(times):.2f}s")
        print(f"  Min: {min(times):.2f}s")
        print(f"  Max: {max(times):.2f}s")

    print(f"\n{'='*70}\n")

    return len(failed) == 0

def main():
    print("[*] Installing dependencies...")
    install_dependencies()

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
        preexec_fn=os.setsid if sys.platform != "win32" else None
    )

    print("[*] Starting qtunnel client...")
    client_proc = subprocess.Popen(
        ["./build/qtunnel_client",
         "127.0.0.1:18443",
         "--listen", "11080",
         "--log-level", "info"],
        stdout=open("test/logs/chrome_stress_client.log", "w"),
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid if sys.platform != "win32" else None
    )

    time.sleep(3)

    try:
        # Verify services started
        if subprocess.run(["pgrep", "-f", "qtunnel_server"],
                         capture_output=True).returncode != 0:
            print("[-] Server failed to start")
            return 1

        if subprocess.run(["pgrep", "-f", "qtunnel_client"],
                         capture_output=True).returncode != 0:
            print("[-] Client failed to start")
            return 1

        # Run Chrome stress test (increased concurrency)
        success = run_chrome_browser_test(
            num_browsers=5,
            pages_per_browser=5,
            proxy_url="http://127.0.0.1:11080"
        )

        # Check for server crashes
        print("[*] Checking server stability...")

        with open("test/logs/chrome_stress_server.log", "r") as f:
            server_log = f.read()
            if "Segmentation fault" in server_log or "segfault" in server_log:
                print("[!] SEGMENTATION FAULT DETECTED!")
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
            print("[!] Some pages failed to load")
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
        try:
            if sys.platform != "win32":
                os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
                os.killpg(os.getpgid(client_proc.pid), signal.SIGTERM)
            else:
                server_proc.terminate()
                client_proc.terminate()
        except:
            pass

        time.sleep(1)
        subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    sys.exit(main())
