#!/usr/bin/env python3
"""Test specific sites to debug failures"""
import subprocess
import time
from playwright.sync_api import sync_playwright

subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(1)

server_proc = subprocess.Popen(
    ["./build/qtunnel_server",
     "--listen", "18443",
     "--cert-file", "test/certs/server.crt",
     "--key-file", "test/certs/server.key",
     "--log-level", "Warn"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

client_proc = subprocess.Popen(
    ["./build/qtunnel_client",
     "127.0.0.1:18443",
     "--listen", "11080",
     "--log-level", "Warn"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

time.sleep(3)

sites = [
    ("https://www.baidu.com/", "Baidu"),
    ("https://www.bilibili.com/", "Bilibili"),
    ("https://www.google.com/", "Google"),
    ("https://www.github.com/", "GitHub"),
]

for url, name in sites:
    try:
        print(f"[*] Testing {name}...", flush=True)
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                proxy={"server": "http://127.0.0.1:11080"},
                args=["--disable-dev-shm-usage", "--no-sandbox"]
            )
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.set_default_timeout(5000)
            
            try:
                start = time.time()
                response = page.goto(url, wait_until="domcontentloaded")
                elapsed = time.time() - start
                title = page.title()
                print(f"[✓] {name}: {response.status if response else 'N/A'} in {elapsed:.2f}s - {title[:30]}")
            except Exception as e:
                print(f"[✗] {name}: {str(e)[:50]}")
            finally:
                context.close()
                browser.close()
    except Exception as e:
        print(f"[!] {name}: {e}")

server_proc.terminate()
client_proc.terminate()
