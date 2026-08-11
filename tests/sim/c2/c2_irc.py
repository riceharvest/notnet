#!/usr/bin/env python3
"""Legacy IRC C2 server for the notnet sim.

Reuses the repo's mock_irc.py flow (001/250/376 -> JOIN, 366 -> auth) but adds
the scriptable command queue: queued /queue/*.json commands are sent as PRIVMSG
from an authorized nick (irc_auth_nicks). Responses from the bot are logged to
evidence.
"""
import json
import os
import socket
import threading
import time
from datetime import datetime, timezone

QUEUE_DIR = os.environ.get("SIM_QUEUE_DIR", "/queue")
EVIDENCE = os.environ.get("SIM_EVIDENCE", "/evidence/irc.log")
AUTH_NICK = os.environ.get("SIM_IRC_NICK", "mockirc")
CHANNEL = os.environ.get("SIM_IRC_CHANNEL", "#notnet")

lock = threading.Lock()
clients = []


def log(line):
    ts = datetime.now(timezone.utc).isoformat()
    with lock:
        with open(EVIDENCE, "a") as f:
            f.write(f"{ts} {line}\n")
        print(f"[{ts}] {line}", flush=True)


def next_command():
    try:
        files = sorted(os.listdir(QUEUE_DIR))
    except FileNotFoundError:
        return None
    for fn in files:
        if not fn.endswith(".json"):
            continue
        path = os.path.join(QUEUE_DIR, fn)
        try:
            with open(path) as f:
                data = json.load(f)
            os.unlink(path)
            return data
        except (json.JSONDecodeError, OSError):
            continue
    return None


def handle_client(conn, addr):
    conn.settimeout(30)
    buf = ""
    nick = "bot"
    channel = CHANNEL
    try:
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
                nick = parts[1] if len(parts) > 1 else "bot"
                conn.sendall((f":mockirc 001 {nick} :mockirc!mockirc@127.0.0.1\r\n").encode())
                conn.sendall((f":mockirc 250 {nick} :Connection counts\r\n").encode())
                conn.sendall((f":mockirc 376 {nick} :End of /MOTD\r\n").encode())
                log(f"IRC CONNECT {addr[0]} nick={nick}")
                break
        for _ in range(5):
            try:
                data = conn.recv(1024).decode(errors="replace")
                buf += data
                if "\r\n" in data:
                    break
            except socket.timeout:
                break
        for line in buf.split("\r\n"):
            line = line.strip()
            if line.startswith("JOIN"):
                parts = line.split()
                channel = parts[1] if len(parts) > 1 else CHANNEL
                conn.sendall((f":mockirc 366 {nick} {channel} :End of /NAMES list\r\n").encode())
                log(f"IRC JOIN {addr[0]} channel={channel}")
                break
        clients.append(conn)
        # queue-driven commands
        deadline = time.time() + 120
        while time.time() < deadline:
            q = next_command()
            if q is not None:
                cmd = q.get("cmd", "status")
                args = q.get("args", "")
                text = f"{cmd} {args}".strip()
                msg = f":{AUTH_NICK}!{AUTH_NICK}@127.0.0.1 PRIVMSG {channel} :{text}\r\n"
                conn.sendall(msg.encode())
                log(f"IRC SERVE {text}")
            try:
                data = conn.recv(4096).decode(errors="replace")
                if data:
                    log(f"IRC RECV {addr[0]}: {data[:200]}")
            except socket.timeout:
                continue
            except (ConnectionError, OSError):
                break
            time.sleep(0.5)
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    port = int(os.environ.get("SIM_IRC_PORT", "6667"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(10)
    log(f"LISTEN IRC on 0.0.0.0:{port} nick={AUTH_NICK} channel={CHANNEL}")
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
