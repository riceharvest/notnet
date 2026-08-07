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
            conn.sendall((':mockirc 001 %s :mockirc!mockirc@127.0.0.1\r\n' % nick).encode())
            # Send RPL_LUSERCHAN (250)
            conn.sendall((':mockirc 250 %s :Connection counts\r\n' % nick).encode())
            # Send RPL_ENDOFMOTD (376) to trigger JOIN
            conn.sendall((':mockirc 376 %s :End of /MOTD\r\n' % nick).encode())
            print("[+] IRC client connected: %s:%d (nick=%s)" % (addr[0], addr[1], nick))
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
            print("[+] Client joined channel: %s" % channel)
            # Send RPL_ENDOFNAMES (366) to signal auth
            conn.sendall((':mockirc 366 %s %s :End of /NAMES list\r\n' % (nick, channel)).encode())
            break

    CLIENTS.append(conn)
    print("[!] Total IRC clients: %d" % len(CLIENTS))

    # Send a test command after 2 seconds
    time.sleep(2)
    try:
        test_cmd = ':mockirc!mockirc@127.0.0.1 PRIVMSG %s :exec uname -a\r\n' % channel
        conn.sendall(test_cmd.encode())
        print("[>] Sent test command: exec uname -a")
    except:
        pass

    # Keep connection alive, read responses
    try:
        while True:
            data = conn.recv(4096).decode(errors='replace')
            if not data:
                break
            print("[<] IRC recv: %s" % data[:200])
    except (socket.timeout, ConnectionError):
        pass

    conn.close()
    print("[-] IRC client disconnected: %s:%d" % (addr[0], addr[1]))

def main():
    if len(sys.argv) < 2:
        print("Usage: mock_irc.py <port>")
        sys.exit(1)
    port = int(sys.argv[1])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(10)
    print("[*] Mock IRC server listening on 0.0.0.0:%d" % port)

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            print("[!] Error: %s" % e)

if __name__ == '__main__':
    main()
