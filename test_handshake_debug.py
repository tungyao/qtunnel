#!/usr/bin/env python3
"""Debug handshake issues"""
import subprocess
import socket
import time
import sys
import threading

# Kill any existing
subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(1)

# Start server and client with DEBUG logging
server_proc = subprocess.Popen(
    ["./build/qtunnel_server",
     "--listen", "18443",
     "--cert-file", "test/certs/server.crt",
     "--key-file", "test/certs/server.key",
     "--log-level", "Debug"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

client_proc = subprocess.Popen(
    ["./build/qtunnel_client",
     "127.0.0.1:18443",
     "--listen", "11080",
     "--log-level", "Debug"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

time.sleep(3)

try:
    # Try to connect and send CONNECT
    print("[*] Connecting to proxy...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("127.0.0.1", 11080))
    print("[✓] Connected")

    print("[*] Sending CONNECT request...")
    request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n"
    sock.sendall(request)
    print(f"[✓] Sent {len(request)} bytes")

    # Wait a bit for processing
    time.sleep(1)

    # Try to read response
    try:
        response = sock.recv(1024)
        print(f"[✓] Got response: {response}")
    except socket.timeout:
        print(f"[-] Timeout waiting for response")

    sock.close()

except Exception as e:
    print(f"[-] Error: {e}")
finally:
    # Give servers time to log
    time.sleep(1)

    # Read client logs
    client_proc.terminate()
    server_proc.terminate()

    stdout, _ = client_proc.communicate(timeout=2)
    print("\n[CLIENT LOGS]")
    for line in stdout.split('\n')[-50:]:
        if line:
            print(line)
