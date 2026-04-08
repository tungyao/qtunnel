#!/usr/bin/env python3
"""Simple CONNECT test"""
import subprocess
import socket
import time
import sys

# Kill any existing
subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(1)

# Start server and client
server_proc = subprocess.Popen(
    ["./build/qtunnel_server",
     "--listen", "18443",
     "--cert-file", "test/certs/server.crt",
     "--key-file", "test/certs/server.key",
     "--log-level", "Debug"],
    stdout=open("test/logs/simple_server.log", "w"),
    stderr=subprocess.STDOUT
)

client_proc = subprocess.Popen(
    ["./build/qtunnel_client",
     "127.0.0.1:18443",
     "--listen", "11080",
     "--log-level", "Debug"],
    stdout=open("test/logs/simple_client.log", "w"),
    stderr=subprocess.STDOUT
)

time.sleep(3)

try:
    # Try to connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    print("[*] Connecting to proxy...")
    sock.connect(("127.0.0.1", 11080))
    print("[✓] Connected")

    # Send CONNECT
    print("[*] Sending CONNECT...")
    sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

    # Try to read response
    print("[*] Waiting for response...")
    response = sock.recv(1024)
    print(f"[✓] Response: {response}")

    sock.close()

except Exception as e:
    print(f"[-] Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    server_proc.terminate()
    client_proc.terminate()
    time.sleep(1)

# Check logs
print("\n[*] Server log tail:")
subprocess.run(["tail", "-20", "test/logs/simple_server.log"])
print("\n[*] Client log tail:")
subprocess.run(["tail", "-20", "test/logs/simple_client.log"])
