#!/usr/bin/env python3
"""RFC 6455 WebSocket C2 server for the notnet sim.

Implements the server side of the bot's ws_connect()/ws_read()/ws_send():

Handshake (protocol.c ~1642):
  client sends: GET <ws_path> HTTP/1.1, Upgrade: websocket, Connection: Upgrade,
                Sec-WebSocket-Key: <base64>, Sec-WebSocket-Version: 13
  server must reply 101 with Sec-WebSocket-Accept = base64(SHA1(key + GUID))
  GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

Frames:
  client -> server frames are MASKED (bot masks with 4 random bytes) — unmask.
  server -> client frames are UNMASKED (we send text frames, FIN+opcode 1).
  Command JSON inside frames: {"cmd":..,"args":..,"secret":"<c2_secret>"}

Queue-driven like the HTTP C2: /queue/*.json served on next WS frame.
Evidence appended to /evidence/ws.log.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
from datetime import datetime, timezone

C2_SECRET = os.environ.get("SIM_C2_SECRET", "mocksecret")
QUEUE_DIR = os.environ.get("SIM_QUEUE_DIR", "/queue")
EVIDENCE = os.environ.get("SIM_EVIDENCE", "/evidence/ws.log")
WS_PATH = os.environ.get("SIM_WS_PATH", "/ws/v1/bot")
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

lock = threading.Lock()
stats = {"connections": 0, "frames": 0, "commands_served": 0}


def log(line):
    ts = datetime.now(timezone.utc).isoformat()
    with lock:
        with open(EVIDENCE, "a") as f:
            f.write(f"{ts} {line}\n")
        print(f"[{ts}] {line}", flush=True)


CHANNEL = "ws"
# Only the sim's attacker bot (docker-compose.sim.yml fixed IP) may receive
# queued driver commands; devices also connect over WS (device.tpl has
# ws_enabled=1) and would otherwise win the queue claim race.
BOT_IP = "172.29.0.9"


def _for_me(fn):
    """True if a queued command file is meant for THIS C2 mock (see c2_http)."""
    for ch in ("http-", "ws-", "irc-"):
        if fn.startswith(ch):
            return ch[:-1] == CHANNEL
    return True


def next_command():
    """Pop the oldest queued command file and return its JSON content, or None.

    Atomic claim via os.rename — shares the queue dir with c2_http.py.
    """
    try:
        files = sorted(os.listdir(QUEUE_DIR))
    except FileNotFoundError:
        return None
    for fn in files:
        if not fn.endswith(".json"):
            continue
        if not _for_me(fn):
            continue
        src = os.path.join(QUEUE_DIR, fn)
        claimed = src + ".claimed"
        try:
            os.rename(src, claimed)  # atomic: only one server wins
        except OSError:
            continue
        try:
            with open(claimed) as f:
                data = json.load(f)
            return data
        except (json.JSONDecodeError, OSError):
            continue
        finally:
            try:
                os.unlink(claimed)
            except OSError:
                pass
    return None


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def read_frame(conn):
    """Read one client frame. Returns (opcode, payload_bytes)."""
    hdr = recv_exact(conn, 2)
    fin = (hdr[0] >> 7) & 1
    opcode = hdr[0] & 0x0F
    masked = (hdr[1] >> 7) & 1
    plen = hdr[1] & 0x7F
    if plen == 126:
        plen = struct.unpack(">H", recv_exact(conn, 2))[0]
    elif plen == 127:
        plen = struct.unpack(">Q", recv_exact(conn, 8))[0]
    mask = recv_exact(conn, 4) if masked else None
    payload = recv_exact(conn, plen)
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


def send_text(conn, text):
    payload = text.encode("utf-8")
    ln = len(payload)
    if ln < 126:
        hdr = bytes([0x81, ln])
    elif ln < 65536:
        hdr = bytes([0x81, 126]) + struct.pack(">H", ln)
    else:
        hdr = bytes([0x81, 127]) + struct.pack(">Q", ln)
    conn.sendall(hdr + payload)


def handle_client(conn, addr):
    conn.settimeout(60)
    try:
        # ---- handshake ----
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace")
        key = None
        for line in head.split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        if not key:
            log(f"WS handshake missing key from {addr[0]}")
            return
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        resp = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        conn.sendall(resp.encode())
        with lock:
            stats["connections"] += 1
        log(f"WS CONNECT {addr[0]}")

        # ---- frames ----
        while True:
            fin, opcode, payload = read_frame(conn)
            if opcode == 0x8:  # close
                log(f"WS CLOSE {addr[0]}")
                return
            if opcode == 0x9:  # ping
                send_text(conn, "")  # pong-ish (empty text); bot doesn't rely on it
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode != 0x1:
                continue
            with lock:
                stats["frames"] += 1
            text = payload.decode("utf-8", errors="replace")
            log(f"WS FRAME {addr[0]}: {text[:300]}")
            try:
                j = json.loads(text)
            except json.JSONDecodeError:
                j = {}
            if j.get("cmd") == "status" and addr[0] == BOT_IP:
                q = next_command()
                if q is not None:
                    with lock:
                        stats["commands_served"] += 1
                    out = json.dumps({"cmd": q.get("cmd", "status"),
                                      "args": q.get("args", ""),
                                      "secret": C2_SECRET})
                    log(f"WS SERVE {out}")
                    send_text(conn, out)
                else:
                    send_text(conn, json.dumps({"status": "ok", "secret": C2_SECRET}))
            else:
                # command response from bot
                send_text(conn, json.dumps({"status": "ok", "secret": C2_SECRET}))
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    port = int(os.environ.get("SIM_WS_PORT", "8081"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    log(f"LISTEN WS on 0.0.0.0:{port} path={WS_PATH} secret={C2_SECRET}")
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
