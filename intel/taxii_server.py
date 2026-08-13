#!/usr/bin/env python3
"""notnet TAXII 2.1 server — dependency-free (stdlib only).

Serves intel/intel-latest.json as a TAXII collection so the repo is a *feed*,
not just a codebase. This is the minimal discovery + collection-media-endpoint
surface a TAXII 2.1 client needs; it does not implement auth or mutation.

Endpoints:
    GET /taxii2/                 -> Discovery
    GET /taxii2/api/collections/ -> Collections
    GET /taxii2/api/collections/{id}/ -> Collection metadata
    GET /taxii2/api/collections/{id}/objects/ -> STIX bundle objects

Run:  python3 intel/taxii_server.py [--port 8080] [--host 127.0.0.1]
"""
import argparse
import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(REPO, "intel", "intel-latest.json")
COLLECTION_ID = "notnet-indicators"
TITLE = "notnet detection intel"


def _load_bundle():
    if not os.path.exists(BUNDLE):
        return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": []}
    with open(BUNDLE, encoding="utf-8") as f:
        return json.load(f)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        if path in ("/taxii2", "/taxii2/"):
            return self._send(200, {
                "title": TITLE,
                "description": "notnet STIX/TAXII feed (see intel/).",
                "default": f"/taxii2/api/",
                "api_roots": ["/taxii2/api/"],
            })
        if path in ("/taxii2/api", "/taxii2/api/"):
            return self._send(200, {
                "title": TITLE,
                "versions": ["application/taxii+json;version=2.1"],
                "collections": f"/taxii2/api/collections/",
            })
        if path in ("/taxii2/api/collections", "/taxii2/api/collections/"):
            return self._send(200, {
                "objects": [{
                    "id": COLLECTION_ID,
                    "title": TITLE,
                    "description": "notnet C2 domains, killswitch domain, CVE modules, wire-format fingerprints, ATT&CK mapping.",
                    "can_read": True,
                    "can_write": False,
                    "media_types": ["application/stix+json;version=2.1"],
                }],
                "spec_version": "2.1",
            })
        if path == f"/taxii2/api/collections/{COLLECTION_ID}":
            return self._send(200, {
                "id": COLLECTION_ID,
                "title": TITLE,
                "description": "notnet detection intel collection.",
                "can_read": True, "can_write": False,
                "media_types": ["application/stix+json;version=2.1"],
            })
        if path == f"/taxii2/api/collections/{COLLECTION_ID}/objects":
            return self._send(200, {
                "objects": _load_bundle().get("objects", []),
                "spec_version": "2.1",
            })
        self._send(404, {"title": "Not Found", "http_status": "404"})

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"notnet TAXII 2.1 server on http://{args.host}:{args.port}/taxii2/")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
