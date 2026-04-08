#!/usr/bin/env python3
"""Test TLS handshake through CONNECT tunnel"""
import subprocess
import socket
import time
import sys
import ssl

subprocess.run(["pkill", "-9", "-f", "qtunnel"], stderr=subprocess.DEVNULL)
time.sleep(1)

server_proc = subprocess.Popen(
    ["./build/qtunnel_server",
     "--listen", "18443",
     "--cert-file", "test/certs/server.crt",
     "--key-file", "test/certs/server.key",
     "--log-level", "Info"],
    stdout=open("test/logs/tls_server.log", "w"),
    stderr=subprocess.STDOUT
)

client_proc = subprocess.Popen(
    ["./build/qtunnel_client",
     "127.0.0.1:18443",
     "--listen", "11080",
     "--log-level", "Info"],
    stdout=open("test/logs/tls_client.log", "w"),
    stderr=subprocess.STDOUT
)

time.sleep(3)

try:
    # Direct TLS test
    print("[*] Testing HTTPS connection through proxy...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("127.0.0.1", 11080))
    
    # Send CONNECT for google.com
    print("[*] Sending CONNECT google.com:443...")
    sock.sendall(b"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com:443\r\n\r\n")
    
    response = sock.recv(1024)
    print(f"[✓] Response: {response[:50]}")
    
    # Now wrap in SSL
    print("[*] Wrapping socket in SSL...")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    ssl_sock = context.wrap_socket(sock, server_hostname="google.com")
    print("[✓] TLS handshake complete!")
    
    # Try to get a page
    print("[*] Sending HTTP request...")
    ssl_sock.sendall(b"GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n")
    
    data = ssl_sock.recv(4096)
    print(f"[✓] Received {len(data)} bytes")
    if b"HTTP/1.1" in data:
        print("[✓] Got HTTP response!")
    
    ssl_sock.close()
    
except Exception as e:
    print(f"[-] Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    server_proc.terminate()
    client_proc.terminate()
    time.sleep(1)

print("\n[*] Server log (last 20 lines):")
subprocess.run(["tail", "-20", "test/logs/tls_server.log"])
print("\n[*] Client log (last 20 lines):")
subprocess.run(["tail", "-20", "test/logs/tls_client.log"])
