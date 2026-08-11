#!/usr/bin/env python3
"""Dead-drop C2 resolution server for the notnet sim.

Serves the plaintext endpoint blob the bot fetches via http_get_url():
  GET /blob?secret=ok  -> server=<drop_server>&port=<drop_port>&secret=<c2_secret>
  GET /blob?secret=bad -> server=<drop_server>&port=<drop_port>&secret=WRONG
  GET /blob?secret=none-> no secret field (fail-closed: bot keeps static config)

Trust model (README, #86): the blob is accepted ONLY when its secret= field
equals the configured c2_secret. The transport is plaintext by design.
"""
import os
import socket
import threading
from datetime import datetime, timezone

EVIDENCE = os.environ.get("SIM_EVIDENCE", "/evidence/deaddrop.log")
DROP_SERVER = os.environ.get("SIM_DROP_SERVER", "mock-http")
DROP_PORT = os.environ.get("SIM_DROP_PORT", "8080")
C2_SECRET = os.environ.get("SIM_C2_SECRET", "mocksecret")

lock = threading.Lock()


def log(line):
    ts = datetime.now(timezone.utc).isoformat()
    with lock:
        with open(EVIDENCE, "a") as f:
            f.write(f"{ts} {line}\n")
        print(f"[{ts}] {line}", flush=True)


def handle_client(conn, addr):
    conn.settimeout(10)
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace")
        reqline = head.split("\r\n")[0]
        path = reqline.split(" ")[1] if len(reqline.split(" ")) > 1 else "/"
        log(f"DEADDROP GET {path} from {addr[0]}")
        secret = ""
        if "?" in path:
            query = path.split("?", 1)[1]
            for kv in query.split("&"):
                if kv.startswith("secret="):
                    secret = kv.split("=", 1)[1]
        if secret == "ok":
            body = f"server={DROP_SERVER}&port={DROP_PORT}&secret={C2_SECRET}"
        elif secret == "bad":
            body = f"server={DROP_SERVER}&port={DROP_PORT}&secret=WRONGSECRET"
        else:
            body = f"server={DROP_SERVER}&port={DROP_PORT}"  # no secret field
        resp = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Deaddrop/1.0\r\n"
            "Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode() + body.encode()
        conn.sendall(resp)
        log(f"DEADDROP RESP {body}")
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    port = int(os.environ.get("SIM_DEADDROP_PORT", "8090"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(10)
    log(f"LISTEN deaddrop on 0.0.0.0:{port}")
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
