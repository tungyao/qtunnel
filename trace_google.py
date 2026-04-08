#!/usr/bin/env python3
"""Detailed trace of Google request"""
import subprocess
import time
import threading

subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(2)

# Start with maximum Debug logging
srv = subprocess.Popen(
    ["./build/qtunnel_server", "--listen", "18443",
     "--cert-file", "test/certs/server.crt", "--key-file", "test/certs/server.key",
     "--log-level", "Debug"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
)

time.sleep(2)

cli = subprocess.Popen(
    ["./build/qtunnel_client", "127.0.0.1:18443", "--listen", "11080",
     "--log-level", "Debug"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
)

time.sleep(4)

# Run curl
print("[*] Running curl test...")
curl = subprocess.Popen(
    ["timeout", "5", "curl", "-v", "--proxy", "http://127.0.0.1:11080",
     "--insecure", "https://www.google.com/", "-I"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
)

# Wait for curl
curl.wait()
print(f"[*] Curl exited with code {curl.returncode}")

time.sleep(2)

# Kill server and client
srv.terminate()
cli.terminate()

# Read full client log
print("\n[*] Last 50 client log lines:")
import subprocess
result = subprocess.run(["tail", "-50", "/root/server/qtunnel/client.log"],
                       capture_output=True, text=True)
for line in result.stdout.split('\n')[-50:]:
    if 'stream=3' in line or 'downlink' in line or 'uplink' in line or 'CONNECT' in line:
        print(line)
