#!/usr/bin/env python3
"""Mock HTTP C2 server for Docker testing.
Simple HTTP server that accepts POST heartbeats and responds with commands.
"""
import json
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

commands_sent = []
heartbeats_received = []

class C2Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode('utf-8') if content_len > 0 else ''
        heartbeats_received.append({
            'time': datetime.now().isoformat(),
            'path': self.path,
            'body': body,
        })
        print(f"[+] HTTP POST {self.path} - {body[:100]}")

        # Respond with a command after first heartbeat
        if len(heartbeats_received) == 1:
            time.sleep(3)
            self.server._queued_command = '{"cmd": "exec", "args": "uname -a"}'
            print(f"[>] Queued command for bot: {self.server._queued_command}")

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def do_GET(self):
        # Poll for commands
        if hasattr(self.server, '_queued_command'):
            cmd = self.server._queued_command
            self.server._queued_command = None
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(cmd.encode())
            print(f"[>] Sent command via GET: {cmd}")
        else:
            self.send_response(204)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[HTTP] {format % args}")

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(('0.0.0.0', port), C2Handler)
    server._queued_command = None
    print(f"[*] Mock HTTP C2 server on 0.0.0.0:{port}")
    print(f"[*] Path: /api/v1/bot")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Mock HTTP server stopped")
        print(f"[!] Heartbeats received: {len(heartbeats_received)}")
        for h in heartbeats_received:
            print(f"    {h['time']} - {h['body'][:80]}")
        server.server_close()

if __name__ == '__main__':
    main()
