#!/usr/bin/env python3
"""Mock HTTP C2 server for Docker testing.
Simple HTTP server that accepts POST heartbeats and responds with commands.
"""
import json
import sys
import time
import socket
import threading
from datetime import datetime

commands_sent = []
heartbeats_received = []

def handle_client(conn, addr):
    """Handle a single HTTP/1.1 keep-alive connection."""
    conn.settimeout(120)  # 2 minute timeout
    buf = b""
    request_count = 0
    content_len = 0
    
    try:
        while True:
            # Read request line + headers
            chunk = conn.recv(4096)
            if not chunk:
                print(f"[HTTP] Client {addr} disconnected after {request_count} requests")
                break
            
            buf += chunk
            
            # Check if we have full headers (ends with \r\n\r\n)
            header_end = buf.find(b"\r\n\r\n")
            if header_end == -1:
                continue
            
            header_data = buf[:header_end].decode('utf-8', errors='replace')
            body_data = buf[header_end + 4:]
            
            # Parse request line
            lines = header_data.split("\r\n")
            request_line = lines[0]
            print(f"[HTTP] {addr}: {request_line}")
            
            if request_line.startswith("POST "):
                request_count += 1
                
                # Parse Content-Length
                content_len = 0
                for h in lines[1:]:
                    if h.lower().startswith("content-length:"):
                        content_len = int(h.split(":")[1].strip())
                        break
                
                # Read body
                while len(body_data) < content_len:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    body_data += chunk
                
                body = body_data[:content_len].decode('utf-8', errors='replace')
                heartbeats_received.append({
                    'time': datetime.now().isoformat(),
                    'path': request_line.split()[1],
                    'body': body,
                })
                print(f"[+] HTTP POST - {body[:120]}")
                
                # Respond with a command after first heartbeat
                if request_count == 1:
                    time.sleep(0.5)
                    response = '{"cmd": "exec", "args": "uname -a"}'
                    print(f"[>] Sending command via POST response: {response}")
                else:
                    response = '{"status": "ok"}'
                
                # Build HTTP/1.1 response
                response_bytes = response.encode('utf-8')
                response_line = "HTTP/1.1 200 OK\r\n"
                response_headers = (
                    f"Server: MockHTTP/1.0\r\n"
                    f"Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(response_bytes)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"Keep-Alive: timeout=60\r\n"
                    f"\r\n"
                )
                conn.sendall(response_line.encode() + response_headers.encode() + response_bytes)
                print(f"[HTTP] Sent {len(response_bytes)} bytes response")
            
            buf = body_data[content_len:]  # Keep any leftover data

    except socket.timeout:
        print(f"[HTTP] Client {addr} timed out after {request_count} requests")
    except ConnectionResetError:
        print(f"[HTTP] Client {addr} reset connection")
    except Exception as e:
        print(f"[HTTP] Client {addr} error: {e}")
    finally:
        conn.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    server.settimeout(5)  # Allow periodic checks
    
    print(f"[*] Mock HTTP C2 server on 0.0.0.0:{port}")
    print(f"[*] Path: /api/v1/bot")
    
    try:
        while True:
            try:
                conn, addr = server.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[-] Mock HTTP server stopped")
        print(f"[!] Heartbeats received: {len(heartbeats_received)}")
        for h in heartbeats_received:
            print(f"    {h['time']} - {h['body'][:80]}")
    finally:
        server.close()

if __name__ == '__main__':
    main()