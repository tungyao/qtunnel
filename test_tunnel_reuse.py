#!/usr/bin/env python3
"""
Test if a single HTTP CONNECT tunnel properly multiplexes multiple requests.
"""
import subprocess
import socket
import ssl
import time
import sys
import os

def test_single_tunnel_multiple_requests():
    """Test multiple requests through one CONNECT tunnel"""

    # Make sure server/client are running
    server_proc = subprocess.Popen(
        ["./build/qtunnel_server",
         "--listen", "18443",
         "--cert-file", "test/certs/server.crt",
         "--key-file", "test/certs/server.key",
         "--log-level", "Info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    client_proc = subprocess.Popen(
        ["./build/qtunnel_client",
         "127.0.0.1:18443",
         "--listen", "11080",
         "--log-level", "error"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(2)

    try:
        # Connect to local proxy
        print("[*] Connecting to proxy...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 11080))

        # Send CONNECT request
        print("[*] Sending CONNECT request...")
        connect_req = b"CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"
        sock.sendall(connect_req)

        # Read response
        response = b""
        sock.settimeout(5)
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
        except socket.timeout:
            pass

        print(f"[*] CONNECT response: {response[:100]}")

        if b"200" not in response:
            print("[-] CONNECT failed!")
            return False

        # Now the tunnel is established, try TLS
        print("[*] Establishing TLS...")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_sock = context.wrap_socket(sock, server_hostname="www.google.com")

        # Make multiple HTTP requests through the tunnel
        requests = [
            b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: keep-alive\r\n\r\n",
            b"GET /images HTTP/1.1\r\nHost: www.google.com\r\nConnection: keep-alive\r\n\r\n",
            b"GET /search?q=test HTTP/1.1\r\nHost: www.google.com\r\nConnection: keep-alive\r\n\r\n",
        ]

        times = []
        for i, req in enumerate(requests):
            start = time.time()
            tls_sock.sendall(req)

            resp = b""
            try:
                tls_sock.settimeout(5)
                while True:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\r\n\r\n" in resp:  # Got headers
                        break
            except (socket.timeout, ssl.SSLError) as e:
                print(f"[-] Request {i+1} failed: {e}")
                return False

            elapsed = time.time() - start
            times.append(elapsed)

            status_line = resp.split(b"\r\n")[0].decode('utf-8', errors='ignore')
            print(f"[✓] Request {i+1}: {status_line} ({elapsed:.2f}s)")

        tls_sock.close()

        print(f"\n[*] Timing summary:")
        print(f"    Request 1: {times[0]:.2f}s")
        print(f"    Request 2: {times[1]:.2f}s")
        print(f"    Request 3: {times[2]:.2f}s")

        # Check if they're serialized (each one takes ~1 second)
        # Or multiplexed (all fast)
        if max(times) < 2.0:
            print("[✓] Requests appear to be multiplexed (all fast)")
            return True
        else:
            print("[!] Requests appear to be serialized (slow)")
            return False

    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        try:
            server_proc.terminate()
            client_proc.terminate()
            time.sleep(1)
            server_proc.kill()
            client_proc.kill()
        except:
            pass

if __name__ == "__main__":
    sys.exit(0 if test_single_tunnel_multiple_requests() else 1)
