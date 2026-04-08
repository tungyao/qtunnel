#!/usr/bin/env python3
"""Detailed CONNECT test with data transmission"""
import subprocess
import socket
import time
import sys

subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(1)

server_proc = subprocess.Popen(
    ["./build/qtunnel_server",
     "--listen", "18443",
     "--cert-file", "test/certs/server.crt",
     "--key-file", "test/certs/server.key",
     "--log-level", "Debug"],
    stdout=open("test/logs/detailed_server.log", "w"),
    stderr=subprocess.STDOUT
)

client_proc = subprocess.Popen(
    ["./build/qtunnel_client",
     "127.0.0.1:18443",
     "--listen", "11080",
     "--log-level", "Debug"],
    stdout=open("test/logs/detailed_client.log", "w"),
    stderr=subprocess.STDOUT
)

time.sleep(3)

try:
    # Connect and send CONNECT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    print("[*] Connecting...")
    sock.connect(("127.0.0.1", 11080))
    print("[✓] Connected")

    print("[*] Sending CONNECT example.com:443...")
    sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    
    print("[*] Waiting for 200 response...")
    response = sock.recv(1024)
    print(f"[✓] Got response: {response[:50]}")
    
    # Now send TLS ClientHello (fake data for testing)
    tls_hello = b"\x16\x03\x01\x00\x4a" + b"\x00" * 70  # TLS 1.0 handshake header + dummy data
    print(f"[*] Sending TLS ClientHello ({len(tls_hello)} bytes)...")
    sock.sendall(tls_hello)
    print("[✓] Sent TLS data")
    
    # Wait a bit for server to process
    time.sleep(2)
    
    sock.close()
    print("[✓] Socket closed")

except Exception as e:
    print(f"[-] Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    server_proc.terminate()
    client_proc.terminate()
    time.sleep(1)

print("\n[*] Server log (last 30 lines):")
subprocess.run(["tail", "-30", "test/logs/detailed_server.log"])
print("\n[*] Client log (last 30 lines):")
subprocess.run(["tail", "-30", "test/logs/detailed_client.log"])
