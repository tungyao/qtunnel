#!/usr/bin/env python3
"""Debug Google failure"""
import subprocess
import time
from playwright.sync_api import sync_playwright

subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(1)

for log_file in ["test/logs/google_server.log", "test/logs/google_client.log"]:
    subprocess.run(["rm", "-f", log_file])

server_proc = subprocess.Popen(
    ["./build/qtunnel_server",
     "--listen", "18443",
     "--cert-file", "test/certs/server.crt",
     "--key-file", "test/certs/server.key",
     "--log-level", "Info"],
    stdout=open("test/logs/google_server.log", "w"),
    stderr=subprocess.STDOUT
)

client_proc = subprocess.Popen(
    ["./build/qtunnel_client",
     "127.0.0.1:18443",
     "--listen", "11080",
     "--log-level", "Info"],
    stdout=open("test/logs/google_client.log", "w"),
    stderr=subprocess.STDOUT
)

time.sleep(3)

try:
    print("[*] Testing Google with logging...", flush=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            proxy={"server": "http://127.0.0.1:11080"},
            args=["--disable-dev-shm-usage", "--no-sandbox"]
        )
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.set_default_timeout(3000)
        
        try:
            page.goto("https://www.google.com/", wait_until="domcontentloaded")
            print("[✓] Google loaded!")
        except Exception as e:
            print(f"[✗] Google timeout: {str(e)[:80]}")
        
        context.close()
        browser.close()
except Exception as e:
    print(f"[!] Error: {e}")
finally:
    server_proc.terminate()
    client_proc.terminate()
    time.sleep(1)

print("\n[*] Server log (CONNECT requests):")
subprocess.run(["grep", "CONNECT", "test/logs/google_server.log"])
print("\n[*] Server log (upstream events):")
subprocess.run(["grep", "-E", "(upstream|CONNECT|TCP|EOF)", "test/logs/google_server.log"])
