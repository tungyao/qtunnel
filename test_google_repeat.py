#!/usr/bin/env python3
import subprocess, time
from playwright.sync_api import sync_playwright

subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(1)

server = subprocess.Popen(
    ["./build/qtunnel_server", "--listen", "18443",
     "--cert-file", "test/certs/server.crt", "--key-file", "test/certs/server.key"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(1)

client = subprocess.Popen(
    ["./build/qtunnel_client", "127.0.0.1:18443", "--listen", "11080"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(2)

results = {"success": 0, "timeout": 0}

print("[*] Running Google test 5 times...")
for i in range(5):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, proxy={"server": "http://127.0.0.1:11080"},
                                       args=["--disable-dev-shm-usage", "--no-sandbox"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.set_default_timeout(3000)
            
            try:
                page.goto("https://www.google.com/", wait_until="domcontentloaded")
                print(f"  [{i+1}] ✓ Success")
                results["success"] += 1
            except:
                print(f"  [{i+1}] ⏱ Timeout")
                results["timeout"] += 1
            finally:
                context.close()
                browser.close()
    except Exception as e:
        print(f"  [{i+1}] ✗ Error: {str(e)[:40]}")

server.terminate()
client.terminate()

print(f"\nResults: {results['success']}/5 successful")
