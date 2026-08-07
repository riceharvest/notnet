#!/usr/bin/env python3
"""Mock IRC C2 server for Docker testing.
Listens on a port, accepts IRC connections, responds to NICK/USER/JOIN,
and sends a test command after connecting.
"""
import socket
import threading
import sys
import time

CLIENTS = []

def handle_client(conn, addr):
    conn.settimeout(20)
    buf = ""
    nick = "bot"
    channel = "#notnet"

    # Read initial IRC handshake
    for _ in range(10):
        try:
            data = conn.recv(1024).decode(errors='replace')
            buf += data
            if '\r\n' in data:
                break
        except socket.timeout:
            break

    # Parse NICK and USER
    for line in buf.split('\r\n'):
        line = line.strip()
        if line.startswith('NICK'):
            parts = line.split()
            nick = parts[1] if len(parts) > 1 else 'bot'
            # Send RPL_WELCOME (001)
            conn.sendall(f':mockirc 001 {nick} mockirc :Welcome to notnet test server\r\n'.encode())
            # Send RPL_LUSERCHAN (250)
            conn.sendall(f':mockirc 250 {nick} :Connection counts\r\n'.encode())
            # Send RPL_ENDOFMOTD (376) to trigger JOIN
            conn.sendall(f':mockirc 376 {nick} :End of /MOTD\r\n'.encode())
            print(f"[+] IRC client connected: {addr[0]}:{addr[1]} (nick={nick})")
            break

    # Read JOIN
    for _ in range(5):
        try:
            data = conn.recv(1024).decode(errors='replace')
            buf += data
            if '\r\n' in data:
                break
        except socket.timeout:
            break

    for line in buf.split('\r\n'):
        line = line.strip()
        if line.startswith('JOIN'):
            parts = line.split()
            channel = parts[1] if len(parts) > 1 else '#notnet'
            print(f"[+] Client joined channel: {channel}")
            # Send RPL_ENDOFNAMES (366) to signal auth
            conn.sendall(f':mockirc 366 {nick} {channel} :End of /NAMES list\r\n'.encode())
            break

    CLIENTS.append(conn)
    print(f"[!] Total IRC clients: {len(CLIENTS)}")

    # Send a test command after 2 seconds
    time.sleep(2)
    try:
        test_cmd = f':mockirc PRIVMSG {channel} :exec uname -a\r\n'
        conn.sendall(test_cmd.encode())
        print(f"[>] Sent test command: exec uname -a")
    except:
        pass

    # Keep connection alive, read responses
    try:
        while True:
            data = conn.recv(4096).decode(errors='replace')
            if not data:
                break
            print(f"[<] IRC recv: {data[:200]}")
    except (socket.timeout, ConnectionError):
        pass

    conn.close()
    print(f"[-] IRC client disconnected: {addr[0]}:{addr[1]}")

def main():
    if len(sys.argv) < 2:
        print("Usage: mock_irc.py <port>")
        sys.exit(1)

    port = int(sys.argv[1])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(10)
    print(f"[*] Mock IRC server listening on 0.0.0.0:{port}")

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == '__main__':
    main()
