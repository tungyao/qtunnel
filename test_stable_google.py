#!/usr/bin/env python3
"""Stable Google test with detailed logging"""
import subprocess
import time
import sys

# Ensure clean slate
subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(2)

print("[*] Starting server...")
server = subprocess.Popen(
    ["./build/qtunnel_server",
     "--listen", "18443",
     "--cert-file", "test/certs/server.crt",
     "--key-file", "test/certs/server.key",
     "--log-level", "Debug"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    universal_newlines=True,
    bufsize=1
)

print("[*] Starting client...")
client = subprocess.Popen(
    ["./build/qtunnel_client",
     "127.0.0.1:18443",
     "--listen", "11080",
     "--log-level", "Debug"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    universal_newlines=True,
    bufsize=1
)

time.sleep(4)

print("[*] Server started. Waiting for client connection...")

# Read initial server output
server_lines = []
for _ in range(100):
    try:
        line = server.stdout.readline()
        if line:
            server_lines.append(line.strip())
            if "h2 mode" in line.lower():
                print("[✓] Server H2 mode active")
                break
    except:
        break

# Read initial client output
client_lines = []
for _ in range(50):
    try:
        line = client.stdout.readline()
        if line:
            client_lines.append(line.strip())
            if "listening" in line.lower():
                print("[✓] Client listening")
                break
    except:
        break

print("\n[*] Starting curl test...")
result = subprocess.run(
    ["timeout", "10", "curl", "-v", "--proxy", "http://127.0.0.1:11080",
     "--insecure", "https://www.google.com/", "-I"],
    capture_output=True,
    text=True
)

print("\nCURL STDERR (first 50 lines):")
for line in result.stderr.split('\n')[:50]:
    print(line)

print(f"\nCURL exit code: {result.returncode}")

# Let server/client process for a moment
time.sleep(2)

# Terminate
server.terminate()
client.terminate()

print("\n[*] Last client logs:")
for line in client_lines[-10:]:
    print(line)
