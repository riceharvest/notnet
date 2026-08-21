#!/usr/bin/env python3
"""SIEM-native output emitters for the notnet IDS (issue #155).

SIEMEmitter fans a single detection event out to any number of SIEM backends,
selected purely by environment variables — all of them are optional and the
emitter is a complete no-op when none are set (default ids_monitor.py
behaviour is unchanged).

Env vars (multiple may be set at once for fanout):

  SIM_SIEM_SYSLOG=host:port   Syslog RFC 5424 over UDP. One datagram per
                              detection, PRI 132 (high) / 130 (medium) /
                              110 (info), structured-data block carries the
                              raw signature fields.
  SIM_SIEM_CEF=file:path      ArcSight Common Event Format v0 lines. Real CEF
                              over TCP line protocol streams one CEF record
                              per newline to a TCP collector; in the sim we
                              append those same records to a file instead so
                              any TCP-line consumer (or `nc`, or Filebeat's
                              file input) can pick them up unchanged.
  SIM_SIEM_ECS=file:path      Elastic Common Schema JSON lines (one object per
                              line), ECS 8.x field names, ready for Logstash
                              json codec / Elastic Security.
  SIM_SIEM_WEBHOOK=url        Structured JSON POSTed to a generic HTTP
                              webhook endpoint (same payload as ECS plus
                              transport metadata).

Example:
    export SIM_SIEM_SYSLOG=splunk.example:514
    export SIM_SIEM_CEF=file:/var/log/notnet-cef.log
    export SIM_SIEM_ECS=file:/var/log/notnet-ecs.json
    export SIM_SIEM_WEBHOOK=https://siem.example/hook/notnet

Every backend failure is swallowed and logged once to stderr: a dead SIEM must
never take down the IDS.
"""
import json
import os
import socket
import sys
import urllib.request
from datetime import datetime, timezone

# sig prefix/class -> (severity name, RFC5424 PRI, CEF 0-10)
_SEV_MAP = {
    "CVE-EXPLOIT": ("high", 132, 9),
    "PAYLOAD-DROP": ("high", 132, 9),
    "SCAN-SWEEP": ("medium", 130, 5),
    "BRUTE-BURST": ("medium", 130, 5),
    "EDR": ("info", 110, 3),
    "HONEYPOT": ("info", 110, 3),
}
_DEFAULT_SEV = ("info", 110, 3)

# Private enterprise number used for our structured-data SD-ID (example/PEN).
_SD_ID = "notnet@32473"


def severity_for(sig):
    """Map a signature name to (name, rfc5424_pri, cef_0_10)."""
    return _SEV_MAP.get(sig, _DEFAULT_SEV)


def _cef_escape(value):
    """Escape a CEF extension value (backslash first, then = and \\n/\\r)."""
    value = str(value)
    value = value.replace("\\", "\\\\")
    value = value.replace("=", "\\=")
    value = value.replace("\n", "\\n").replace("\r", "\\r")
    return value


def format_rfc5424(sig, src, dst, detail, timestamp=None, pri=None):
    """RFC 5424 syslog line: <PRI>1 TS HOST APP PROCID MSGID SD MSG."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    if pri is None:
        pri = severity_for(sig)[1]
    sd = (
        '[%s sig="%s" src="%s" dst="%s" severity="%s"]'
        % (_SD_ID, sig, src, dst, severity_for(sig)[0])
    )
    # RFC 5424 TIMESTAMP is RFC 3339 with mandatory TZ offset; isoformat from
    # datetime.now(timezone.utc) already qualifies ("+00:00" suffix).
    return '<%d>1 %s notnet-ids notnet-ids - - %s %s' % (pri, timestamp, sd, detail)


def format_cef(sig, src, dst, detail):
    """ArcSight CEF v0 record (7 pipes in the header + extension fields).

    Header: CEF:0|deviceVendor|deviceProduct|deviceVersion|signatureID|name|severity|
    """
    _, _, cef_sev = severity_for(sig)
    header = "CEF:0|notnet|ids|1.0|%s|%s|%d|" % (sig, sig, cef_sev)
    ext = "src=%s dst=%s msg=%s" % (_cef_escape(src), _cef_escape(dst), _cef_escape(detail))
    return header + ext


def format_ecs(sig, src, dst, detail, timestamp=None):
    """Elastic Common Schema (8.x) event as a single JSON object."""
    _, _, cef_sev = severity_for(sig)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "@timestamp": timestamp,
        "ecs": {"version": "8.0.0"},
        "event": {"kind": "alert", "severity": cef_sev, "module": "notnet-ids"},
        "source": {"ip": src},
        "destination": {"ip": dst},
        "message": detail,
        "labels": {"signature": sig},
    }


def format_webhook(sig, src, dst, detail, timestamp=None):
    """Generic webhook JSON payload (ECS body + routing metadata)."""
    sev_name = severity_for(sig)[0]
    payload = format_ecs(sig, src, dst, detail, timestamp)
    payload["notnet"] = {"signature": sig, "severity": sev_name}
    return payload


class SIEMEmitter:
    """Fan-out emitter built from SIEM_* environment variables.

    Backends are discovered once at construction; pass ``env`` explicitly for
    tests. With no variables set the emitter does nothing.
    """

    def __init__(self, env=None):
        env = os.environ if env is None else env
        self.backends = []
        syslog = env.get("SIM_SIEM_SYSLOG", "").strip()
        if syslog:
            host, _, port = syslog.rpartition(":")
            self.backends.append(("syslog", host, int(port)))
        cef = env.get("SIM_SIEM_CEF", "")
        if cef.startswith("file:"):
            self.backends.append(("cef_file", cef[len("file:"):], None))
        ecs = env.get("SIM_SIEM_ECS", "")
        if ecs.startswith("file:"):
            self.backends.append(("ecs_file", ecs[len("file:"):], None))
        hook = env.get("SIM_SIEM_WEBHOOK", "").strip()
        if hook:
            self.backends.append(("webhook", hook, None))

    @property
    def enabled(self):
        return bool(self.backends)

    def emit(self, sig, src, dst, detail, timestamp=None):
        """Send one detection to every configured backend (fanout).

        Never raises: individual backend errors go to stderr only.
        """
        if not self.backends:
            return
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        for backend in self.backends:
            kind = backend[0]
            try:
                if kind == "syslog":
                    self._send_syslog(backend[1], backend[2],
                                      format_rfc5424(sig, src, dst, detail, ts))
                elif kind == "cef_file":
                    self._append_line(backend[1],
                                      format_cef(sig, src, dst, detail))
                elif kind == "ecs_file":
                    self._append_line(backend[1], json.dumps(
                        format_ecs(sig, src, dst, detail, ts)))
                elif kind == "webhook":
                    self._post_webhook(backend[1],
                                       format_webhook(sig, src, dst, detail, ts))
            except Exception as exc:  # noqa: BLE001 - SIEM must not kill IDS
                print("%s SIEM emit failed (%s): %s" % (ts, kind, exc),
                      file=sys.stderr, flush=True)

    @staticmethod
    def _send_syslog(host, port, message):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode("utf-8"), (host, port))
        finally:
            sock.close()

    @staticmethod
    def _append_line(path, line):
        # Same bytes a real CEF/ECS TCP-line collector would receive.
        with open(path, "a") as f:
            f.write(line + "\n")

    @staticmethod
    def _post_webhook(url, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": "notnet-ids/1.0"})
        urllib.request.urlopen(req, timeout=5).close()


# Shared singleton so ids_monitor.alert() pays no construction cost per alert.
_default_emitter = None


def get_emitter():
    global _default_emitter
    if _default_emitter is None:
        _default_emitter = SIEMEmitter()
    return _default_emitter
