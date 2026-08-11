#!/usr/bin/env python3
"""Mock Redis server for spread testing.

Responds to the simplified Redis exploit used by notnet's spreader:
- PING -> +PONG
- CONFIG SET dir /path -> +OK
- SET key val -> +OK
- SAVE -> +OK then +PONG
- AUTH pass -> +PONG (accepts any password)
"""
import socket
import threading
import sys

def handle_client(conn, addr):
    conn.settimeout(30)
    try:
        print(f"[Redis] Connection from {addr[0]}:{addr[1]}")
        
        while True:
            data = conn.recv(4096)
            if not data:
                break
            
            text = data.decode(errors='replace')
            print(f"[Redis] <- {text[:200]}")
            
            # The bot pipelines multiple commands in one send (CONFIG SET,
            # SET, SAVE, PING). Respond to each command line in order so
            # the final +PONG proves the whole sequence succeeded.
            lines = [ln.strip() for ln in text.split("\r\n") if ln.strip()]
            for ln in lines:
                upper = ln.upper()
                if upper.startswith("PING"):
                    conn.sendall(b"+PONG\r\n")
                elif upper.startswith("AUTH"):
                    conn.sendall(b"+OK\r\n")
                elif upper.startswith("CONFIG"):
                    conn.sendall(b"+OK\r\n")
                elif upper.startswith("SET"):
                    conn.sendall(b"+OK\r\n")
                elif upper.startswith("SAVE"):
                    conn.sendall(b"+OK\r\n")
                elif upper.startswith("DEL"):
                    conn.sendall(b"+OK\r\n")
                else:
                    conn.sendall(b"+PONG\r\n")
                print(f"[Redis] -> {ln[:20]} response")
    except Exception as e:
        print(f"[Redis] Error: {e}")
    finally:
        conn.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 6379
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(10)
    print(f"[*] Mock Redis server on 0.0.0.0:{port}")
    
    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == '__main__':
    main()
