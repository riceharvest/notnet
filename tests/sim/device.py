#!/usr/bin/env python3
"""Generic multi-service device emulator for the notnet sim.

One container = one device from fleet.yaml. Profile-driven via env vars:

  DEVICE_ID        device name (also used as bot_tag on infection)
  DEVICE_TYPE      smart-fridge | tbk-dvr | huawei-hg532 | realtek | linux-pc |
                   windows-pc | nas | redis-cache | redis-auth | printer |
                   smart-tv | honeypot-* (handled by Cowrie, not this image)
  DEVICE_PORTS     comma list, e.g. "23,80" (each starts a listener)
  TELNET_CREDS     "user:pass" (comma list for multi)
  SSH_CREDS        "user:pass"
  SMB_CREDS        "user:pass"
  REDIS_PASS       "" = no auth, else AUTH requires this password
  CVE              CVE-2024-3721 | CVE-2017-17215 | CVE-2021-35395 |
                   CVE-2018-10088 | CVE-2020-29583 | CVE-2015-2051 | none
  PATCHED          true/false — patched CVE devices return a generic banner (probe miss)
  PATCHED_PARTIAL  true/false — banner matches but verify fails (no drop)
  EDR_BLOCK        true/false — refuse to execute the payload + log EDR-ALERT
  LOCKOUT          true/false — after 5 failed auths, reject all for 60s
  PAYLOAD_URL      http://host:port/bot/notnet (what a real drop would fetch)
  EVIDENCE         /evidence/<id>.log

Realism contract: this emulator is the INFECTION-CAPABLE victim — on a verified
drop command it actually executes the payload (subprocess), which is how the
sim models real propagation (device runs the notnet binary -> joins C2 with
bot_tag=<device-id>). Cowrie devices (honeypots) never execute.
"""
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone

DEVICE_ID = os.environ.get("DEVICE_ID", "device")
DEVICE_TYPE = os.environ.get("DEVICE_TYPE", "linux-pc")
DEVICE_PORTS = [int(p) for p in os.environ.get("DEVICE_PORTS", "22").split(",") if p]
TELNET_CREDS = [tuple(c.split(":", 1)) for c in os.environ.get("TELNET_CREDS", "").split(",") if ":" in c]
SSH_CREDS = [tuple(c.split(":", 1)) for c in os.environ.get("SSH_CREDS", "").split(",") if ":" in c]
SMB_CREDS = [tuple(c.split(":", 1)) for c in os.environ.get("SMB_CREDS", "").split(",") if ":" in c]
REDIS_PASS = os.environ.get("REDIS_PASS", "")
CVE = os.environ.get("CVE", "none")
WEB_TITLE = os.environ.get("WEB_TITLE", "")   # vendor banner for generic web UI
PATCHED = os.environ.get("PATCHED", "false").lower() == "true"
PATCHED_PARTIAL = os.environ.get("PATCHED_PARTIAL", "false").lower() == "true"
EDR_BLOCK = os.environ.get("EDR_BLOCK", "false").lower() == "true"
LOCKOUT = os.environ.get("LOCKOUT", "false").lower() == "true"
SSH_KEY_ONLY = os.environ.get("SSH_KEY_ONLY", "false").lower() == "true"
SMB1_DISABLED = os.environ.get("SMB1_DISABLED", "false").lower() == "true"
STRONG_CREDS = os.environ.get("STRONG_CREDS", "false").lower() == "true"
PERSIST = os.environ.get("PERSIST", "false").lower() == "true"
PAYLOAD_URL = os.environ.get("PAYLOAD_URL", "http://c2:8443/bot/notnet")
EVIDENCE = os.environ.get("EVIDENCE", f"/evidence/{DEVICE_ID}.log")

lock = threading.Lock()
# Lockout state is keyed per (service, source IP) so a brute on one service
# or from one source never contaminates another (issue #298).
failed_auths = {}    # (proto, src_ip) -> consecutive failures since last success/reset
lockout_until = {}   # (proto, src_ip) -> epoch ts until which auths are rejected
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 60


def log(line):
    ts = datetime.now(timezone.utc).isoformat()
    with lock:
        with open(EVIDENCE, "a") as f:
            f.write(f"{ts} {line}\n")
            f.flush()
            os.fsync(f.fileno())
        print(f"[{ts}] {line}", flush=True)


def check_lockout(proto, src_ip):
    """Return True if (proto, src_ip) is in lockout (reject all auths)."""
    if not LOCKOUT:
        return False
    # Shared state read from per-connection threads: take the module lock so
    # we never observe a torn/partial update of lockout_until.
    with lock:
        return time.time() < lockout_until.get((proto, src_ip), 0.0)


def record_failure(proto, src_ip):
    key = (proto, src_ip)
    if not LOCKOUT:
        return
    msg = None
    with lock:
        n = failed_auths.get(key, 0) + 1
        failed_auths[key] = n
        if n >= LOCKOUT_THRESHOLD:
            lockout_until[key] = time.time() + LOCKOUT_SECONDS
            msg = f"LOCKOUT triggered for {proto} from {src_ip} after {n} failures ({LOCKOUT_SECONDS}s)"
            failed_auths[key] = 0
    # log() acquires `lock` itself, so it must run outside the held lock.
    if msg:
        log(msg)


def record_success(proto, src_ip):
    """Reset the failure counter for (proto, src_ip) on successful auth (#298)."""
    if not LOCKOUT:
        return
    with lock:
        failed_auths.pop((proto, src_ip), None)


def cred_ok(creds, user, password):
    return (user, password) in creds


# ─────────────────────────── HTTP/CVE handlers ───────────────────────────

def is_drop_cmd(cmd):
    """#305: drop-vs-verify dispatch keys on the actual payload-delivery
    signature — the C2 download URL /bot/notnet?token=<tok> (or its opt-in
    legacy ?secret= fallback) that build_drop_url() embeds in every drop
    command — never on the downloader name ('wget'), which can also appear
    inside benign probe/verify traffic."""
    return "/bot/notnet?" in (cmd or "")

def http_response(conn, body, ctype="text/html", code="200 OK", extra=""):
    body_b = body.encode("utf-8") if isinstance(body, str) else body
    resp = (
        f"HTTP/1.0 {code}\r\n"
        "Server: " + ctype.split(";")[0] + "\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body_b)}\r\n"
        "Connection: close\r\n"
        + (extra + "\r\n" if extra else "")
        + "\r\n"
    ).encode() + body_b
    try:
        conn.sendall(resp)
    except OSError:
        pass


def handle_http_cve(conn, addr):
    """Serve the CVE HTTP endpoints (TBK / HG532 / Realtek) on port 80/37215."""
    conn.settimeout(10)
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace")
        body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
        lines = head.split("\r\n")
        reqline = lines[0]
        method, path = reqline.split(" ")[:2]
        clen = 0
        headers = {}
        for h in lines[1:]:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if "content-length" in headers:
            clen = int(headers["content-length"])
        while len(body) < clen:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
        body_txt = body[:clen].decode("utf-8", errors="replace")

        if CVE == "CVE-2024-3721":  # TBK DVR
            if PATCHED:
                http_response(conn, "<html><title>Generic NVR</title></html>")
                log(f"TBK probe on patched device {addr[0]} -> miss")
                return
            if PATCHED_PARTIAL:
                http_response(conn, "<html><title>TBK DVR</title></html>")
                log(f"TBK verify on partial-patch {addr[0]} -> no echo")
                return
            if method == "GET" and path.startswith("/"):
                http_response(conn, "<html><title>TBK DVR-4104</title><body>TBK DVR system</body></html>")
                log(f"TBK probe {addr[0]}: GET {path}")
                return
            if method == "POST" and path.startswith("/device.rsp"):
                # verify/drop: mdc=<urlencoded cmd> ; response echoes the cmd output
                q = path.split("?", 1)[1] if "?" in path else ""
                params = urllib.parse.parse_qs(q)
                mdc = params.get("mdc", [""])[0]
                cmd = urllib.parse.unquote(mdc)
                log(f"TBK POST {addr[0]}: {path[:200]} body={body_txt[:200]}")
                if not cmd.strip():
                    # #305: an empty mdc is not a verify — no echo.
                    http_response(conn, "TBK 400", code="400 Bad Request")
                    log(f"TBK POST empty mdc -> ignored")
                elif is_drop_cmd(cmd):  # #305: drop signature, not 'wget'
                    http_response(conn, "TBK ok: " + cmd)
                    log(f"TBK DROP received cmd={cmd!r}")
                    execute_drop(cmd)
                else:
                    http_response(conn, "TBK echo: " + cmd)
                    log(f"TBK VERIFY cmd={cmd!r} -> echoed")
                return
            http_response(conn, "TBK 404")
            return

        if CVE == "CVE-2017-17215":  # Huawei HG532 (port 37215)
            if PATCHED:
                http_response(conn, "<html>404 Not Found</html>", code="404 Not Found")
                log(f"HG532 probe on patched device {addr[0]} -> miss")
                return
            if PATCHED_PARTIAL:
                # Banner/service still answers (SOAP envelope), but the
                # injection no longer executes — verify must fail.
                http_response(conn, '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:UpgradeResponse xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewStatusURL>HUAWEIUPNP-PATCHED</NewStatusURL></u:UpgradeResponse></s:Body></s:Envelope>')
                log(f"HG532 verify on partial-patch {addr[0]} -> no echo (patched)")
                return
            if method == "POST" and "/ctrlt/DeviceUpgrade_1" in path:
                soap_action = headers.get("soapaction", "").strip().strip('"')
                log(f"HG532 POST {addr[0]} SOAPAction={soap_action[:100]} body={body_txt[:200]}")
                # #307: CVE-2017-17215 requires SOAPAction
                # urn:schemas-upnp-org:service:WANPPPConnection:1#DeviceUpgrade
                # (what the module sends); anything else gets no success
                # envelope and no drop.
                if soap_action != "urn:schemas-upnp-org:service:WANPPPConnection:1#DeviceUpgrade":
                    http_response(conn, '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>UPnPError</s:Fault></s:Body></s:Envelope>', code="500 Internal Server Error")
                    log(f"HG532 POST refused: missing/invalid SOAPAction {soap_action[:100]!r}")
                    return
                cmd = extract_cmd(body_txt)
                if is_drop_cmd(cmd):  # #305: drop signature, not 'wget'
                    http_response(conn, '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:UpgradeResponse xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewStatusURL>HUAWEIUPNP</NewStatusURL></u:UpgradeResponse></s:Body></s:Envelope>')
                    log(f"HG532 DROP received cmd={cmd!r}")
                    execute_drop(cmd)
                else:
                    # probe/verify: HUAWEIUPNP envelope
                    http_response(conn, '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:UpgradeResponse xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewStatusURL>HUAWEIUPNP</NewStatusURL></u:UpgradeResponse></s:Body></s:Envelope>')
                    log(f"HG532 VERIFY/probe ok (HUAWEIUPNP)")
                return
            http_response(conn, "<html>404</html>", code="404 Not Found")
            return

        if CVE == "CVE-2021-35395":  # Realtek Jungle SDK
            if PATCHED:
                http_response(conn, "<html><title>Apache2 Debian</title></html>", ctype="text/html; charset=utf-8", extra="Server: Apache/2.4.41 (Debian)")
                log(f"Realtek probe on patched device {addr[0]} -> miss")
                return
            if PATCHED_PARTIAL:
                # Boa banner still served but sysCmd injection is fixed:
                # verify gets a generic response, not the echoed token.
                http_response(conn, "<html>ok</html>", extra="Server: Boa/0.94.14rc21")
                log(f"Realtek verify on partial-patch {addr[0]} -> no echo (patched)")
                return
            if method == "GET" and path.startswith("/"):
                http_response(conn, "<html><title>Router</title></html>", extra="Server: Boa/0.94.14rc21")
                log(f"Realtek probe {addr[0]}: GET {path} -> Boa")
                return
            if method == "POST" and "/boafrm/formSysCmd" in path:
                params = urllib.parse.parse_qs(body_txt)
                sys_cmd = params.get("sysCmd", [""])[0]
                log(f"Realtek POST {addr[0]}: sysCmd={sys_cmd[:200]}")
                if not sys_cmd.strip():
                    # #305: an empty sysCmd is not a verify — no echo.
                    http_response(conn, "400", code="400 Bad Request")
                    log(f"Realtek POST empty sysCmd -> ignored")
                elif is_drop_cmd(sys_cmd):  # #305: drop signature, not 'wget'
                    http_response(conn, sys_cmd)
                    log(f"Realtek DROP received cmd={sys_cmd!r}")
                    execute_drop(sys_cmd)
                else:
                    http_response(conn, sys_cmd)  # echo token
                    log(f"Realtek VERIFY cmd={sys_cmd!r} -> echoed")
                return
            http_response(conn, "404", code="404 Not Found")
            return

        if CVE == "CVE-2018-10088":  # Boa httpd formAuth (router)
            if PATCHED:
                # Generic nginx banner -> probe miss (and arch=x86)
                http_response(conn, "<html>Welcome</html>",
                              extra="Server: nginx/1.18.0")
                log(f"BOA probe on patched device {addr[0]} -> miss")
                return
            if PATCHED_PARTIAL:
                # Boa banner still served, but formAuth injection is
                # fixed: verify gets a generic response, no token echo.
                http_response(conn, "<html>login</html>", extra="Server: Boa/0.94.14rc21")
                log(f"BOA verify on partial-patch {addr[0]} -> no echo (patched)")
                return
            if method == "GET":
                http_response(conn, "<html><title>Router Login</title></html>", extra="Server: Boa/0.94.14rc21")
                log(f"BOA probe {addr[0]}: GET {path} -> Boa")
                return
            if method == "POST" and "/boafrm/formAuth" in path:
                params = urllib.parse.parse_qs(body_txt)
                # parse_qs already percent-decodes the value; do NOT run
                # unquote_plus here or a literal '+' inside the injected
                # command (chmod +x) collapses into a space.
                cmd = (params.get("cmd", [""])[0])
                log(f"BOA POST {addr[0]}: cmd={cmd[:200]}")
                if not cmd.strip():
                    # #305: an empty cmd is not a verify — no echo.
                    http_response(conn, "Boa 400", code="400 Bad Request")
                    log(f"BOA POST empty cmd -> ignored")
                elif is_drop_cmd(cmd):  # #305: drop signature, not 'wget'
                    http_response(conn, "Boa ok: " + cmd)
                    log(f"BOA DROP received cmd={cmd!r}")
                    execute_drop(cmd)
                else:
                    http_response(conn, "Boa echo: " + cmd)
                    log(f"BOA VERIFY cmd={cmd!r} -> echoed")
                return
            http_response(conn, "404", code="404 Not Found")
            return

        if CVE == "CVE-2020-29583":  # Zyxel zysh (USG/ZyWALL)
            if PATCHED:
                http_response(conn, "<html>404 Not Found</html>", code="404 Not Found")
                log(f"ZYXEL probe on patched device {addr[0]} -> miss")
                return
            if PATCHED_PARTIAL:
                # Zyxel banner still answers but zysh exec is fixed.
                http_response(conn, "<html><title>Zyxel</title></html>")
                log(f"ZYXEL verify on partial-patch {addr[0]} -> no echo (patched)")
                return
            if method == "GET":
                http_response(conn, "<html><title>Zyxel Communications Corp.</title><body>Zyxel USG login</body></html>")
                log(f"ZYXEL probe {addr[0]}: GET {path} -> zyxel banner")
                return
            if method == "POST" and "/ztp/cgi-bin/handle" in path:
                params = urllib.parse.parse_qs(body_txt)
                # shape: command=zysh<space><cmd> — parse_qs already
                # percent-decoded; strip the zysh prefix for execution.
                command = params.get("command", [""])[0]
                cmd = command[len("zysh "):] if command.startswith("zysh ") else command
                log(f"ZYXEL POST {addr[0]}: command={command[:200]}")
                if not cmd.strip():
                    # #305: an empty command is not a verify — no echo.
                    http_response(conn, "zysh 400", code="400 Bad Request")
                    log(f"ZYXEL POST empty command -> ignored")
                elif is_drop_cmd(cmd):  # #305: drop signature, not 'wget'
                    http_response(conn, "zysh ok: " + cmd)
                    log(f"ZYXEL DROP received cmd={cmd!r}")
                    execute_drop(cmd)
                else:
                    http_response(conn, "zysh echo: " + cmd)
                    log(f"ZYXEL VERIFY cmd={cmd!r} -> echoed")
                return
            http_response(conn, "404", code="404 Not Found")
            return

        if CVE == "CVE-2015-2051":  # D-Link HNAP (DIR-645/815, port 8080)
            if PATCHED:
                http_response(conn, "<html>404 Not Found</html>", code="404 Not Found")
                log(f"HNAP probe on patched device {addr[0]} -> miss")
                return
            if PATCHED_PARTIAL:
                # HNAP1 marker still served; SOAPAction injection fixed.
                http_response(conn, "HNAP1")
                log(f"HNAP verify on partial-patch {addr[0]} -> no echo (patched)")
                return
            if method == "GET":
                http_response(conn, "HNAP1")
                log(f"HNAP probe {addr[0]}: GET {path} -> HNAP1 marker")
                return
            if method == "POST" and path.startswith("/HNAP1"):
                soap_action = headers.get("soapaction", "")
                log(f"HNAP POST {addr[0]} SOAPAction={soap_action[:200]}")
                # #307: CVE-2015-2051 rides the SOAPAction header of an
                # /HNAP1 request shaped "http://purenetworks.com/HNAP1/
                # <Action>/`cmd`" (what the module sends). Requests without
                # that shape get a fault, never an echo or a drop.
                if not (soap_action.startswith('"http://purenetworks.com/HNAP1/')
                        and "`" in soap_action):
                    http_response(conn, "HNAP1 fault", code="500 Internal Server Error")
                    log(f"HNAP POST refused: missing/invalid SOAPAction {soap_action[:100]!r}")
                    return
                # injection rides inside backticks in SOAPAction
                m = re.search(r"`([^`]*)`", soap_action)
                cmd = m.group(1) if m else ""
                if not cmd.strip():
                    # #305: an empty injection is not a verify — no echo.
                    http_response(conn, "HNAP1 400", code="400 Bad Request")
                    log(f"HNAP POST empty injection -> ignored")
                elif is_drop_cmd(cmd):  # #305: drop signature, not 'wget'
                    http_response(conn, "HNAP1 ok: " + cmd)
                    log(f"HNAP DROP received cmd={cmd!r}")
                    execute_drop(cmd)
                else:
                    http_response(conn, "HNAP1 echo: " + cmd)
                    log(f"HNAP VERIFY cmd={cmd!r} -> echoed")
                return
            http_response(conn, "404", code="404 Not Found")
            return

        # generic web device (smart-fridge/tv/printer web UI, or target-web)
        title = WEB_TITLE if WEB_TITLE else DEVICE_ID
        http_response(conn, f"<html><title>{title}</title><body>{title}</body></html>")
        log(f"WEB {addr[0]}: {method} {path}")
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def extract_cmd(body):
    """Pull the injected command out of an HG532 SOAP body (crude but matches)."""
    import re
    m = re.search(r"<(?:NewStatusURL|NewDownloadURL)>([^<]*)<", body)
    return m.group(1) if m else body[:200]


def execute_drop(cmd):
    """Actually execute the payload command — models real propagation."""
    global EDR_BLOCK
    log(f"EXECUTING DROP: {cmd[:200]}")
    if EDR_BLOCK:
        log("EDR-ALERT: suspicious payload execution blocked (edr_block=true)")
        return
    # S7 persistence: a device with persist=true models cron/systemd by
    # remembering the drop command and relaunching it after a container
    # restart (device_entrypoint.sh runs /app/persist.sh at boot).
    if PERSIST:
        try:
            with open("/app/persist.sh", "a") as f:
                f.write(cmd + "\n")
            log("PERSIST recorded drop command for reboot relaunch")
        except OSError as e:
            log(f"PERSIST record failed: {e}")
    try:
        # Strip background '&' so we can wait a moment for the download to land
        subprocess.Popen(cmd, shell=True, start_new_session=True)
        log("DROP spawned")
    except Exception as e:
        log(f"DROP exec error: {e}")


# ─────────────────────────── Telnet handler ───────────────────────────

IAC = 0xFF
IAC_SB = 0xFA
IAC_SE = 0xF0
IAC_WILL = 0xFB
IAC_WONT = 0xFC
IAC_DO = 0xFD
IAC_DONT = 0xFE


def strip_iac(buf):
    """Strip telnet IAC (RFC 854) escape sequences from buf.

    Returns (clean, consumed, replies):
      clean    - buf with IAC sequences removed (escaped 0xFF kept as one)
      consumed - how many leading bytes of buf were fully processed; an
                 incomplete trailing sequence is NOT consumed so the caller
                 can wait for more bytes
      replies  - minimal negotiation refusals: WILL->DONT, DO->WONT
    """
    out = bytearray()
    replies = bytearray()
    i, n = 0, len(buf)
    while i < n:
        if buf[i] != IAC:
            out.append(buf[i])
            i += 1
            continue
        if i + 1 >= n:
            break  # incomplete sequence at end of buffer
        cmd = buf[i + 1]
        if cmd == IAC:  # escaped literal 0xFF
            out.append(IAC)
            i += 2
        elif cmd in (IAC_WILL, IAC_WONT, IAC_DO, IAC_DONT):
            if i + 2 >= n:
                break  # option byte not arrived yet
            opt = buf[i + 2]
            if cmd == IAC_WILL:
                replies += bytes((IAC, IAC_DONT, opt))
            elif cmd == IAC_DO:
                replies += bytes((IAC, IAC_WONT, opt))
            i += 3
        elif cmd == IAC_SB:
            j = i + 2
            while j + 1 < n and not (buf[j] == IAC and buf[j + 1] == IAC_SE):
                j += 1
            if j + 1 >= n:
                break  # subnegotiation not terminated yet
            i = j + 2
        else:
            # two-byte commands (NOP/DM/BRK/AYT/...) — drop
            i += 2
    return bytes(out), i, bytes(replies)


class LineReader:
    """Line reader that strips IAC sequences with a bounded buffer.

    Keeps leftover bytes between readline() calls so pipelined credentials
    (user+password in one packet) are parsed line-by-line instead of being
    swallowed whole by a single recv (issue #278)."""

    def __init__(self, conn, max_buf=4096):
        self.conn = conn
        self.max_buf = max_buf
        self.raw = b""    # unprocessed bytes incl. incomplete IAC sequences
        self.clean = b""  # decoded stream awaiting newline

    def _fill(self):
        chunk = self.conn.recv(256)
        if not chunk:
            return False
        self.raw += chunk
        clean, consumed, replies = strip_iac(self.raw)
        self.raw = self.raw[consumed:]
        self.clean += clean
        if replies:
            try:
                self.conn.sendall(replies)
            except OSError:
                pass
        if len(self.clean) > self.max_buf or len(self.raw) > self.max_buf:
            raise ValueError("auth input exceeded buffer limit")
        return True

    def readline(self):
        """Return the next CRLF/LF-terminated line, stripped; None on EOF."""
        while True:
            idx = self.clean.find(b"\n")
            if idx != -1:
                line = self.clean[:idx].rstrip(b"\r").decode(errors="replace")
                self.clean = self.clean[idx + 1:]
                return line.strip()
            if not self._fill():
                return None


def handle_telnet(conn, addr):
    conn.settimeout(15)
    try:
        conn.sendall(b"\r\n" + DEVICE_ID.encode() + b" login: ")
        reader = LineReader(conn)
        user = reader.readline()
        if user is None:
            return
        conn.sendall(b"Password: ")
        password = reader.readline()
        if password is None:
            return
        if check_lockout("telnet", addr[0]):
            log(f"TELNET {addr[0]} auth {user} REJECTED (lockout)")
            conn.sendall(b"Login incorrect\r\n")
            return
        if cred_ok(TELNET_CREDS, user, password):
            record_success("telnet", addr[0])
            log(f"TELNET {addr[0]} AUTH OK {user}:{password}")
            conn.sendall(b"# ")
            # read drop command
            try:
                cmd_raw = conn.recv(4096)
                cmd, _, _ = strip_iac(cmd_raw)
                cmd = cmd.decode(errors="replace")
                log(f"TELNET {addr[0]} CMD: {cmd.strip()[:200]}")
                if "wget" in cmd:
                    execute_drop(cmd.strip())
                    conn.sendall(b"# ")
            except socket.timeout:
                pass
        else:
            record_failure("telnet", addr[0])
            log(f"TELNET {addr[0]} AUTH FAIL {user}:{password}")
            conn.sendall(b"Login incorrect\r\n")
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ─────────────────────────── SSH handler ───────────────────────────

def handle_ssh(conn, addr):
    """Realistic SSH flow matching try_login_ssh_with_timeout:
    server banner -> client banner -> 'Username: ' -> user -> 'Password: ' ->
    pass -> '# ' on success. The bot sends creds as separate lines, not
    'user pass' on one line (that was the old mock's wrong assumption)."""
    conn.settimeout(15)
    try:
        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
        # read client banner (SSH-2.0-Notnet)
        reader = LineReader(conn)
        banner = reader.readline()
        if banner is None:
            return
        conn.sendall(b"Username: ")
        user = reader.readline()
        if user is None:
            return
        conn.sendall(b"Password: ")
        password = reader.readline()
        if password is None:
            return
        if SSH_KEY_ONLY:
            # Modern sshd: PasswordAuthentication no — key auth only.
            # The bot only brute-forces passwords, so this must always fail.
            log(f"SSH {addr[0]} REJECTED (key-only auth, password auth disabled)")
            conn.sendall(b"Permission denied (publickey)\r\n")
            return
        if check_lockout("ssh", addr[0]):
            log(f"SSH {addr[0]} auth {user} REJECTED (lockout)")
            conn.sendall(b"Permission denied\r\n")
            return
        if cred_ok(SSH_CREDS, user, password):
            record_success("ssh", addr[0])
            log(f"SSH {addr[0]} AUTH OK {user}:{password}")
            conn.sendall(b"# \r\n")
            try:
                cmd_raw = conn.recv(4096)
                cmd, _, _ = strip_iac(cmd_raw)
                cmd = cmd.decode(errors="replace")
                log(f"SSH {addr[0]} CMD: {cmd.strip()[:200]}")
                if "wget" in cmd:
                    execute_drop(cmd.strip())
            except socket.timeout:
                pass
        else:
            record_failure("ssh", addr[0])
            log(f"SSH {addr[0]} AUTH FAIL {user}:{password}")
            conn.sendall(b"Permission denied\r\n")
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ─────────────────────────── SMB handler ───────────────────────────

def smb_status_response(conn, status, uid=0):
    """SMB1 response header: 0xFF SMB + 32-byte header with NT status.
    Bot's smb1_transaction requires offset >= 38 (4 prefix + 32 header +
    word count + byte count), so send 40 bytes: header + word count(2) +
    byte count(2)."""
    hdr = bytearray(36)
    hdr[0:4] = b"\xFFSMB"
    hdr[4] = 0x72  # SMB_COM_NEGOTIATE (harmless for both)
    hdr[5:9] = status.to_bytes(4, "little")
    hdr[10:12] = (0x0001).to_bytes(2, "little")  # flags2
    hdr[26:28] = uid.to_bytes(2, "little")
    hdr[28:30] = (1).to_bytes(2, "little")  # mid
    # word count 0, byte count 0
    body = bytes([0x00, 0x00, 0x00, 0x00])
    try:
        conn.sendall(bytes(hdr) + body)
    except OSError:
        pass


def handle_smb(conn, addr):
    conn.settimeout(15)
    try:
        # SMB1 negotiate request arrives first
        data = conn.recv(1024)
        if not data:
            return
        log(f"SMB {addr[0]} NEGOTIATE ({len(data)} bytes)")
        if SMB1_DISABLED:
            # Modern Windows: SMB1 removed/disabled. The bot only speaks
            # SMB1, so the whole vector must fail here.
            log(f"SMB {addr[0]} REJECTED (SMB1 disabled)")
            smb_status_response(conn, 0xC00000BB)  # STATUS_NOT_SUPPORTED
            return
        smb_status_response(conn, 0)  # STATUS_SUCCESS
        # session setup with creds
        data = conn.recv(4096)
        if not data:
            return
        # Parse credentials from the session-setup body. The bot's
        # smb1_session_setup sends [prefix][32B header][24B params] then:
        # password (NUL-terminated), account (NUL-terminated), primary group
        # (empty), native OS "Linux". The declared password length lives at
        # params[12:14], i.e. wire offset 48.
        import re
        account = ""
        password = ""
        try:
            pw_len = int.from_bytes(data[48:50], "little")
            pos = 60  # past prefix + header + 24-byte param block
            password = data[pos : pos + pw_len].decode("latin-1", "replace")
            end = data.find(b"\x00", pos + pw_len)
            if end != -1:
                account = data[pos + pw_len : end].decode("latin-1", "replace")
        except (IndexError, ValueError):
            pass
        if not account:
            # fallback: scan printable NUL-terminated tokens; password and
            # account are the two immediately before the native OS string
            try:
                toks = re.findall(rb"([\x20-\x7e]{1,64})\x00", data)
                i = len(toks) - 1 - toks[::-1].index(b"Linux")
                if i >= 2:
                    password = toks[i - 2].decode("latin-1", "replace")
                    account = toks[i - 1].decode("latin-1", "replace")
            except ValueError:
                pass
        if check_lockout("smb", addr[0]):
            log(f"SMB {addr[0]} auth REJECTED (lockout)")
            smb_status_response(conn, 0xC000006A)  # STATUS_LOGON_FAILURE
            return
        ok = cred_ok(SMB_CREDS, account, password) if SMB_CREDS else False
        if ok:
            record_success("smb", addr[0])
            log(f"SMB {addr[0]} AUTH OK account={account}")
            smb_status_response(conn, 0, uid=30000)
            # read drop command (raw bytes after setup)
            try:
                cmd = conn.recv(4096).decode(errors="replace")
                log(f"SMB {addr[0]} CMD: {cmd.strip()[:200]}")
                if "wget" in cmd:
                    execute_drop(cmd.strip())
            except socket.timeout:
                pass
        else:
            record_failure("smb", addr[0])
            log(f"SMB {addr[0]} AUTH FAIL account={account}")
            smb_status_response(conn, 0xC000006A)
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ─────────────────────────── RDP handler ───────────────────────────

def handle_rdp(conn, addr):
    """Honest X.224-shaped responder. The bot's rdp_* functions all check
    buf[0]==0x03 && buf[1]==0xC0 on every response; we reply with a TPKT
    header + payload for each of the ~9 handshake steps. Auth-confirmation
    only (matches README)."""
    conn.settimeout(15)
    try:
        for step in range(9):
            data = conn.recv(4096)
            if not data:
                return
            log(f"RDP {addr[0]} STEP {step} ({len(data)} bytes)")
            # TPKT 0x03 0xC0 + length + X.224 data
            resp = bytes([0x03, 0xC0, 0x00, 0x08, 0x02, 0xF0, 0x80, 0x00])
            conn.sendall(resp)
        # after handshake, the drop command may follow
        try:
            cmd = conn.recv(4096).decode(errors="replace")
            log(f"RDP {addr[0]} CMD: {cmd.strip()[:200]}")
            if "wget" in cmd:
                execute_drop(cmd.strip())
        except socket.timeout:
            pass
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ─────────────────────────── Redis handler ───────────────────────────

def handle_redis(conn, addr):
    conn.settimeout(15)
    try:
        authed = (REDIS_PASS == "")
        while True:
            data = conn.recv(4096)
            if not data:
                return
            text = data.decode(errors="replace")
            log(f"REDIS {addr[0]} <- {text[:200]}")
            lines = [ln.strip() for ln in text.split("\r\n") if ln.strip()]
            for ln in lines:
                upper = ln.upper()
                if upper.startswith("AUTH"):
                    parts = ln.split()
                    if len(parts) >= 2 and parts[1] == REDIS_PASS:
                        authed = True
                        record_success("redis", addr[0])
                        conn.sendall(b"+OK\r\n")
                        log(f"REDIS {addr[0]} AUTH OK")
                    else:
                        authed = False
                        record_failure("redis", addr[0])
                        conn.sendall(b"-ERR invalid password\r\n")
                        log(f"REDIS {addr[0]} AUTH FAIL")
                elif not authed:
                    conn.sendall(b"-NOAUTH Authentication required.\r\n")
                elif upper.startswith("PING"):
                    conn.sendall(b"+PONG\r\n")
                elif upper.startswith("CONFIG"):
                    conn.sendall(b"+OK\r\n")
                elif upper.startswith("SET"):
                    conn.sendall(b"+OK\r\n")
                elif upper.startswith("SAVE"):
                    conn.sendall(b"+OK\r\n")
                elif upper.startswith("DEL"):
                    conn.sendall(b"+OK\r\n")
                elif upper.startswith("GET"):
                    conn.sendall(b"$-1\r\n")
                else:
                    conn.sendall(b"+OK\r\n")
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ─────────────────────────── dispatch ───────────────────────────

def dispatch(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(32)
    log(f"LISTEN {DEVICE_ID} type={DEVICE_TYPE} port={port} cve={CVE} patched={PATCHED} partial={PATCHED_PARTIAL} edr={EDR_BLOCK} lockout={LOCKOUT}")
    while True:
        try:
            conn, addr = srv.accept()
            if port == 23:
                t = threading.Thread(target=handle_telnet, args=(conn, addr), daemon=True)
            elif port == 22:
                t = threading.Thread(target=handle_ssh, args=(conn, addr), daemon=True)
            elif port == 445:
                t = threading.Thread(target=handle_smb, args=(conn, addr), daemon=True)
            elif port == 3389:
                t = threading.Thread(target=handle_rdp, args=(conn, addr), daemon=True)
            elif port == 6379:
                t = threading.Thread(target=handle_redis, args=(conn, addr), daemon=True)
            else:
                t = threading.Thread(target=handle_http_cve, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break


def main():
    if not DEVICE_PORTS:
        log(f"ERROR no ports configured")
        sys.exit(1)
    threads = [threading.Thread(target=dispatch, args=(p,), daemon=True) for p in DEVICE_PORTS]
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
