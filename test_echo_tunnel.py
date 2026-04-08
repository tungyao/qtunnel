#!/usr/bin/env python3
"""Test CONNECT tunnel with local echo server"""
import subprocess
import socket
import time
import threading

subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
subprocess.run(["pkill", "-9", "-f", "nc"], stderr=subprocess.DEVNULL)
time.sleep(1)

# Start a simple echo server on port 9999
echo_proc = subprocess.Popen(
    ["nc", "-l", "-p", "9999"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

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
    print("[*] Testing CONNECT tunnel with echo server on 127.0.0.1:9999...")
    
    # Connect to proxy
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(("127.0.0.1", 11080))
    print("[✓] Connected to proxy")
    
    # Send CONNECT to localhost:9999
    print("[*] Sending CONNECT localhost:9999...")
    sock.sendall(b"CONNECT localhost:9999 HTTP/1.1\r\nHost: localhost:9999\r\n\r\n")
    
    # Receive 200 response
    response = sock.recv(1024)
    print(f"[✓] Got 200 response: {response[:30]}")
    
    # Send test data through tunnel
    print("[*] Sending test data through tunnel...")
    sock.sendall(b"HELLO WORLD\n")
    
    # Receive echo response
    print("[*] Waiting for echo response...")
    data = sock.recv(1024)
    print(f"[✓] Received: {data}")
    
    if data == b"HELLO WORLD\n":
        print("[✓] Echo tunnel works!")
    else:
        print(f"[?] Unexpected response: {data}")
    
    sock.close()
    
except Exception as e:
    print(f"[-] Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    echo_proc.terminate()
    server_proc.terminate()
    client_proc.terminate()
    time.sleep(1)

print("\n[*] Server log (last 15 lines):")
subprocess.run(["tail", "-15", "test/logs/echo_server.log"])
