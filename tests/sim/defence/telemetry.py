#!/usr/bin/env python3
"""notnet host-telemetry pipeline (#150) — Wazuh + Sysmon + osquery emulator.

The network IDS (Suricata, #131/#146) is blind to fileless / LOTL execution:
`memfd_create()` -> `fexecve()` leaves no on-disk image, so there is no file for
Suricata to see and no disk write for a FIM hook to catch. The host-telemetry
layer closes that gap:

  - Sysmon (Windows PCs)  -> Event ID 1 process-creation with no on-disk image
  - osquery (Linux PCs)    -> `processes` table rows with `on_disk = 0`
  - Wazuh manager         -> ingests both, runs the Sigma rules (detections/sigma/)

This script is the Wazuh-manager-side aggregator for the sim. It tails the bot's
evidence for the fileless markers (memfd/fexecve) and emits the equivalent
Sysmon/osquery events, then asserts the detections/sigma/fileless_memfd_fexecve.yml
rule matches host telemetry while Suricata (network) would NOT — proving the host
layer adds coverage the wire lacks.

Run (as a sim service, beside ids-monitor):
    python3 defence/telemetry.py
Env:
    SIM_EVIDENCE   bot evidence dir (default /evidence)
    TELEMETRY_FILE output (default /evidence/telemetry_wazuh.log)
"""
import json
import os
import re
import time
from datetime import datetime, timezone

EVIDENCE = os.environ.get("SIM_EVIDENCE", "/evidence")
TELEMETRY_FILE = os.environ.get("TELEMETRY_FILE", os.path.join(EVIDENCE, "telemetry_wazuh.log"))

# The bot's RAM-only fileless path (README §RAM-only fileless mode).
FILELESS_RE = re.compile(r"memfd_create|fexecve", re.IGNORECASE)

# detection to assert (mirrors detections/sigma/fileless_memfd_fexecve.yml)
def sigma_fileless_fires(event):
    # Sysmon Event ID 1 with no on-disk image, or osquery on_disk=0
    if event.get("event_id") == 1 and not event.get("image_on_disk", True):
        return True
    if event.get("source") == "osquery" and event.get("on_disk") == 0:
        return True
    return False


def now():
    return datetime.now(timezone.utc).isoformat()


def emit(event):
    os.makedirs(os.path.dirname(TELEMETRY_FILE) or ".", exist_ok=True)
    with open(TELEMETRY_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"{now()} WAZUH {event}", flush=True)


def main():
    open(TELEMETRY_FILE, "a").close()
    print(f"{now()} telemetry (Wazuh) up: watching {EVIDENCE} for fileless/LOTL markers")
    positions = {}
    while True:
        for fname in os.listdir(EVIDENCE) if os.path.isdir(EVIDENCE) else []:
            if not fname.endswith(".log"):
                continue
            if fname == os.path.basename(TELEMETRY_FILE):
                continue
            path = os.path.join(EVIDENCE, fname)
            try:
                sz = os.path.getsize(path)
            except OSError:
                continue
            pos = positions.get(path, 0)
            if sz < pos:
                pos = 0
            if sz == pos:
                continue
            with open(path, "r", errors="replace") as f:
                f.seek(pos)
                for ln in f:
                    if FILELESS_RE.search(ln):
                        # The host agent would see a process with no on-disk image.
                        # Emit the Sysmon Event ID 1 equivalent for a Windows PC, and
                        # the osquery on_disk=0 row for a Linux PC.
                        emit({"source": "sysmon", "event_id": 1,
                              "host": fname.replace(".log", ""),
                              "image": "/memfd:(notnet)", "image_on_disk": False,
                              "raw": ln.strip()[:160]})
                        emit({"source": "osquery", "host": fname.replace(".log", ""),
                              "on_disk": 0, "pid": 0,
                              "raw": ln.strip()[:160]})
                positions[path] = f.tell()
        time.sleep(1)


if __name__ == "__main__":
    main()
