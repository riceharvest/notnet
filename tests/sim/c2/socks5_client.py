#!/usr/bin/env python3
"""SOCKS5 client probe for the notnet sim (S7 remaining-parity).

Connects to a SOCKS5 proxy (RFC 1928) with RFC 1929 user/pass auth
(token), CONNECTs to a target, and sends an HTTP GET through the tunnel.
Prints the SOCKS5 handshake result + HTTP status so the driver can verify
real proxied traffic (not just a bound listener).

Canonical location: tests/sim/c2/socks5_client.py (this file). It is mounted
into the sim-c2 container by tests/sim/docker-compose.realc2.yml. Do not copy
it into c2-server/ — CI fails on stray duplicates (issue #194).

Usage:
  socks5_client.py <proxy_host> <proxy_port> <target_host> <target_port>
                   <token> [http_path]
"""
import socket
import struct
import sys


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("EOF during SOCKS5 handshake")
        buf += chunk
    return buf


def main():
    proxy_host, proxy_port = sys.argv[1], int(sys.argv[2])
    tgt_host, tgt_port = sys.argv[3], int(sys.argv[4])
    token = sys.argv[5].encode()
    path = sys.argv[6] if len(sys.argv) > 6 else "/"

    s = socket.create_connection((proxy_host, proxy_port), timeout=10)
    # 1. Greeting: VER=5, NMETHODS=1, method=0x02 (user/pass)
    s.sendall(b"\x05\x01\x02")
    resp = recv_exact(s, 2)
    if resp != b"\x05\x02":
        print(f"SOCKS5 FAIL greeting: {resp!r}")
        sys.exit(1)

    # 2. RFC 1929 auth: VER=1, ULEN, UNAME, PLEN, PASSWD
    uname = b"sim"
    s.sendall(b"\x01" + bytes([len(uname)]) + uname + bytes([len(token)]) + token)
    resp = recv_exact(s, 2)
    if resp != b"\x01\x00":
        print(f"SOCKS5 FAIL auth: {resp!r}")
        sys.exit(1)
    print("SOCKS5 AUTH OK")

    # 3. CONNECT: VER=5, CMD=1, RSV=0, ATYP=1 (IPv4)
    ip = socket.inet_aton(tgt_host)
    s.sendall(b"\x05\x01\x00\x01" + ip + struct.pack(">H", tgt_port))
    resp = recv_exact(s, 10)
    if resp[1] != 0x00:
        print(f"SOCKS5 FAIL CONNECT rep={resp[1]}")
        sys.exit(1)
    print("SOCKS5 CONNECT OK")

    # 4. HTTP GET through the tunnel
    req = f"GET {path} HTTP/1.0\r\nHost: {tgt_host}\r\n\r\n".encode()
    s.sendall(req)
    s.settimeout(10)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    status = data.split(b"\r\n", 1)[0].decode(errors="replace")
    print(f"HTTP {status} ({len(data)} bytes)")
    s.close()


if __name__ == "__main__":
    main()
