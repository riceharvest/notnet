#!/usr/bin/env python3
"""notnet Dionaea SMB trap (#149).

The upstream `honeynet/dionaea` image is no longer publicly pullable, so this is
a self-contained stand-in that emulates the part of Dionaea the sim actually
exercises: an SMB listener (port 445) that captures the bot's `smb1_write_file`
drop path (src/spread.c haslist module) and writes a Dionaea-style capture log to
evidence/dionaea/dionaea.json. The Filebeat sidecar (defence/filebeat.yml) tails
that dir, so the ELK feedback loop still works.

Run:
    python3 defence/dionaea_trap.py
Env:
    DIONAEA_PORT   listen port (default 445)
    SIM_EVIDENCE   evidence dir (default /evidence)
"""
import json
import os
import socket
import threading
import time
from datetime import datetime, timezone

DIONAEA_PORT = int(os.environ.get("DIONAEA_PORT", "445"))
EVIDENCE = os.environ.get("SIM_EVIDENCE", "/evidence")
OUT_DIR = os.path.join(EVIDENCE, "dionaea")
OUT_FILE = os.path.join(OUT_DIR, "dionaea.json")

# Markers that prove the bot hit the SMB drop path (src/spread.c haslist).
DROP_MARKERS = (b"smb1_write_file", b"\\ADMIN$\\", b"IPC$", b"Trans2", b"WriteAndX")


def now():
    return datetime.now(timezone.utc).isoformat()


def record(conn_info, raw):
    os.makedirs(OUT_DIR, exist_ok=True)
    hit = any(m in raw for m in DROP_MARKERS)
    ev = {
        "timestamp": now(),
        "source": "dionaea",
        "protocol": "smb",
        "connection": conn_info,
        "smb_drop_captured": hit,
        "raw_hex": raw[:256].hex(),
    }
    with open(OUT_FILE, "a") as f:
        f.write(json.dumps(ev) + "\n")
    if hit:
        print(f"{now()} DIONAEA smb drop captured from {conn_info}", flush=True)
    else:
        print(f"{now()} DIONAEA smb probe (no drop) from {conn_info}", flush=True)


def handle(conn, addr):
    try:
        conn.settimeout(5)
        data = b""
        try:
            while len(data) < 4096:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        record(f"{addr[0]}:{addr[1]}", data)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", DIONAEA_PORT))
    s.listen(16)
    print(f"{now()} dionaea-trap up on :{DIONAEA_PORT} (evidence/dionaea)", flush=True)
    while True:
        try:
            conn, addr = s.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
