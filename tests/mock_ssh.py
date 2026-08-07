#!/usr/bin/env python3
"""Mock SSH server for spread testing.

Responds to the simplified SSH handshake used by notnet's spreader:
- Sends SSH-2.0 banner on connect
- Accepts 'user pass\r\n' as auth credentials
- Returns '#\r\n' on successful login
"""
import socket
import threading
import sys
import re

def handle_client(conn, addr):
    conn.settimeout(30)
    try:
        # Send SSH banner
        conn.sendall(b"SSH-2.0-MockSSH\r\n")
        
        # Read credentials: notnet sends "user pass\r\n"
        creds = b""
        while len(creds) < 2048:
            chunk = conn.recv(4096)
            if not chunk:
                break
            creds += chunk
            if b"\r\n" in creds:
                break
        
        parts = creds.strip().split()
        user = parts[0].decode(errors='replace') if len(parts) >= 1 else ""
        password = parts[1].decode(errors='replace') if len(parts) >= 2 else ""
        
        print(f"[SSH] Auth attempt: {user}:{password} from {addr[0]}:{addr[1]}")
        
        # Accept any credentials
        if user and password:
            conn.sendall(b"# \r\n")
            print(f"[SSH] Login OK: {user}:{password}")
            
            # Read and echo install command
            try:
                cmd = conn.recv(4096).decode(errors='replace')
                if cmd:
                    print(f"[SSH] Installed: {cmd.strip()}")
            except socket.timeout:
                pass
        else:
            conn.sendall(b"ERROR\r\n")
    except Exception as e:
        print(f"[SSH] Error: {e}")
    finally:
        conn.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 22
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(10)
    print(f"[*] Mock SSH server on 0.0.0.0:{port}")
    
    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == '__main__':
    main()
