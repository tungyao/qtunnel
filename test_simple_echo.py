#!/usr/bin/env python3
"""Test CONNECT tunnel with simple echo server"""
import subprocess
import socket
import time
import threading
import sys

subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(1)

# Start echo server in a thread
def run_echo_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 9999))
    server.listen(1)
    print("[server] Listening on 127.0.0.1:9999", file=sys.stderr)
    try:
        while True:
            conn, addr = server.accept()
            print(f"[server] Connection from {addr}", file=sys.stderr)
            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"[server] Got {len(data)} bytes, echoing back", file=sys.stderr)
                    conn.sendall(data)
            finally:
                conn.close()
    finally:
        server.close()

echo_thread = threading.Thread(target=run_echo_server, daemon=True)
echo_thread.start()
time.sleep(0.5)

server_proc = subprocess.Popen(
    ["./build/qtunnel_server",
     "--listen", "18443",
     "--cert-file", "test/certs/server.crt",
     "--key-file", "test/certs/server.key",
     "--log-level", "Info"],
    stdout=open("test/logs/echo_server.log", "w"),
    stderr=subprocess.STDOUT
)

client_proc = subprocess.Popen(
    ["./build/qtunnel_client",
     "127.0.0.1:18443",
     "--listen", "11080",
     "--log-level", "Info"],
    stdout=open("test/logs/echo_client.log", "w"),
    stderr=subprocess.STDOUT
)

time.sleep(3)

try:
    print("[*] Testing CONNECT tunnel with echo server...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("127.0.0.1", 11080))
    print("[✓] Connected to proxy")
    
    print("[*] Sending CONNECT 127.0.0.1:9999...")
    sock.sendall(b"CONNECT 127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n")
    
    response = sock.recv(1024)
    print(f"[✓] Got response: {response[:40]}")
    
    print("[*] Sending test data...")
    sock.sendall(b"HELLO")
    
    print("[*] Waiting for echo...")
    data = sock.recv(1024)
    print(f"[✓] Got: {data}")
    
    sock.close()
    print("[✓] Test passed!")
    
except Exception as e:
    print(f"[-] Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    server_proc.terminate()
    client_proc.terminate()
    time.sleep(1)

print("\n[*] Server upstream events:")
subprocess.run(["grep", "upstream", "test/logs/echo_server.log"])
