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
  CVE              CVE-2024-3721 | CVE-2017-17215 | CVE-2021-35395 | none
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
PATCHED = os.environ.get("PATCHED", "false").lower() == "true"
PATCHED_PARTIAL = os.environ.get("PATCHED_PARTIAL", "false").lower() == "true"
EDR_BLOCK = os.environ.get("EDR_BLOCK", "false").lower() == "true"
LOCKOUT = os.environ.get("LOCKOUT", "false").lower() == "true"
SSH_KEY_ONLY = os.environ.get("SSH_KEY_ONLY", "false").lower() == "true"
SMB1_DISABLED = os.environ.get("SMB1_DISABLED", "false").lower() == "true"
STRONG_CREDS = os.environ.get("STRONG_CREDS", "false").lower() == "true"
PAYLOAD_URL = os.environ.get("PAYLOAD_URL", "http://c2:8443/bot/notnet")
EVIDENCE = os.environ.get("EVIDENCE", f"/evidence/{DEVICE_ID}.log")

lock = threading.Lock()
failed_auths = 0
lockout_until = 0.0


def log(line):
    ts = datetime.now(timezone.utc).isoformat()
    with lock:
        with open(EVIDENCE, "a") as f:
            f.write(f"{ts} {line}\n")
        print(f"[{ts}] {line}", flush=True)


def check_lockout():
    """Return True if the device is in lockout (reject all auths)."""
    global lockout_until
    if not LOCKOUT:
        return False
    if time.time() < lockout_until:
        return True
    return False


def record_failure():
    global failed_auths, lockout_until
    if not LOCKOUT:
        return
    failed_auths += 1
    if failed_auths >= 5:
        lockout_until = time.time() + 60
        log(f"LOCKOUT triggered after {failed_auths} failures (60s)")
        failed_auths = 0


def cred_ok(creds, user, password):
    return (user, password) in creds


# ─────────────────────────── HTTP/CVE handlers ───────────────────────────

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
                # verify echoes token back; drop executes payload
                if "wget" in cmd:
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
                soap_action = headers.get("soapaction", "")
                log(f"HG532 POST {addr[0]} SOAPAction={soap_action[:100]} body={body_txt[:200]}")
                if "wget" in body_txt:
                    http_response(conn, '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:UpgradeResponse xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewStatusURL>HUAWEIUPNP</NewStatusURL></u:UpgradeResponse></s:Body></s:Envelope>')
                    log(f"HG532 DROP received (wget in body)")
                    execute_drop(extract_cmd(body_txt))
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
                if "wget" in sys_cmd:
                    http_response(conn, sys_cmd)
                    log(f"Realtek DROP received cmd={sys_cmd!r}")
                    execute_drop(sys_cmd)
                else:
                    http_response(conn, sys_cmd)  # echo token
                    log(f"Realtek VERIFY cmd={sys_cmd!r} -> echoed")
                return
            http_response(conn, "404", code="404 Not Found")
            return

        # generic web device (smart-fridge/tv/printer web UI, or target-web)
        http_response(conn, f"<html><title>{DEVICE_ID}</title><body>device web UI</body></html>")
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
    try:
        # Strip background '&' so we can wait a moment for the download to land
        subprocess.Popen(cmd, shell=True, start_new_session=True)
        log("DROP spawned")
    except Exception as e:
        log(f"DROP exec error: {e}")


# ─────────────────────────── Telnet handler ───────────────────────────

def handle_telnet(conn, addr):
    conn.settimeout(15)
    try:
        conn.sendall(b"\r\n" + DEVICE_ID.encode() + b" login: ")
        buf = b""
        while not buf.endswith(b"\r\n"):
            chunk = conn.recv(256)
            if not chunk:
                return
            buf += chunk
        user = buf.strip().decode(errors="replace")
        conn.sendall(b"Password: ")
        buf = b""
        while not buf.endswith(b"\r\n"):
            chunk = conn.recv(256)
            if not chunk:
                return
            buf += chunk
        password = buf.strip().decode(errors="replace")
        if check_lockout():
            log(f"TELNET {addr[0]} auth {user} REJECTED (lockout)")
            conn.sendall(b"Login incorrect\r\n")
            return
        if cred_ok(TELNET_CREDS, user, password):
            log(f"TELNET {addr[0]} AUTH OK {user}:{password}")
            conn.sendall(b"# ")
            # read drop command
            try:
                cmd = conn.recv(4096).decode(errors="replace")
                log(f"TELNET {addr[0]} CMD: {cmd.strip()[:200]}")
                if "wget" in cmd:
                    execute_drop(cmd.strip())
                    conn.sendall(b"# ")
            except socket.timeout:
                pass
        else:
            record_failure()
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
        banner = b""
        while b"\r\n" not in banner:
            chunk = conn.recv(1024)
            if not chunk:
                return
            banner += chunk
        conn.sendall(b"Username: ")
        user_buf = b""
        while b"\r\n" not in user_buf:
            chunk = conn.recv(1024)
            if not chunk:
                return
            user_buf += chunk
        user = user_buf.strip().decode(errors="replace")
        conn.sendall(b"Password: ")
        pass_buf = b""
        while b"\r\n" not in pass_buf:
            chunk = conn.recv(1024)
            if not chunk:
                return
            pass_buf += chunk
        password = pass_buf.strip().decode(errors="replace")
        if SSH_KEY_ONLY:
            # Modern sshd: PasswordAuthentication no — key auth only.
            # The bot only brute-forces passwords, so this must always fail.
            log(f"SSH {addr[0]} REJECTED (key-only auth, password auth disabled)")
            conn.sendall(b"Permission denied (publickey)\r\n")
            return
        if check_lockout():
            log(f"SSH {addr[0]} auth {user} REJECTED (lockout)")
            conn.sendall(b"Permission denied\r\n")
            return
        if cred_ok(SSH_CREDS, user, password):
            log(f"SSH {addr[0]} AUTH OK {user}:{password}")
            conn.sendall(b"# \r\n")
            try:
                cmd = conn.recv(4096).decode(errors="replace")
                log(f"SSH {addr[0]} CMD: {cmd.strip()[:200]}")
                if "wget" in cmd:
                    execute_drop(cmd.strip())
            except socket.timeout:
                pass
        else:
            record_failure()
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
        # crude parse: password and account are NUL-terminated ASCII in the body
        try:
            text = data.decode("latin-1")
            # find account name near the end: last printable token before \x00\x00
            import re
            matches = re.findall(rb"([\x20-\x7e]{1,64})\x00", data)
            account = ""
            password = ""
            # the drop command follows after auth in the same stream
            if matches:
                account = matches[-1].decode(errors="replace")
            # extract password: typically second-to-last or search after "pass"
        except Exception:
            account = ""
        if check_lockout():
            log(f"SMB {addr[0]} auth REJECTED (lockout)")
            smb_status_response(conn, 0xC000006A)  # STATUS_LOGON_FAILURE
            return
        ok = any(u == account for u, _ in SMB_CREDS) if SMB_CREDS else False
        if ok:
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
            record_failure()
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
                        conn.sendall(b"+OK\r\n")
                        log(f"REDIS {addr[0]} AUTH OK")
                    else:
                        authed = False
                        record_failure()
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
