#!/usr/bin/env python3
"""Generate the device compose override + per-device notnet.conf from fleet.yaml.

Outputs:
  tests/sim/docker-compose.fleet.yml  (device services; used as an override file)
  tests/sim/conf/generated/notnet-<id>.conf  (per-device bot config, baked into
                                              /etc/notnet.conf via the device image
                                              entrypoint template + bot_tag)

The bot's payload executes on a device -> reads /etc/notnet.conf -> joins the
C2 with bot_tag=<device-id>, which is how the driver tracks infection.
"""
import os
import sys

try:
    import yaml
except ImportError:
    print("need pyyaml: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

BASE = os.path.dirname(os.path.abspath(__file__))
FLEET = os.path.join(BASE, "fleet.yaml")
OUT_COMPOSE = os.path.join(BASE, "docker-compose.fleet.yml")
OUT_CONF_DIR = os.path.join(BASE, "conf", "generated")

C2_SECRET = os.environ.get("SIM_C2_SECRET", "mocksecret")
HTTP_SERVER = os.environ.get("SIM_HTTP_SERVER", "c2")
HTTP_PORT = os.environ.get("SIM_HTTP_PORT", "8080")
WS_SERVER = os.environ.get("SIM_WS_SERVER", "c2-ws")
WS_PORT = os.environ.get("SIM_WS_PORT", "8081")
PAYLOAD_HOST = os.environ.get("SIM_PAYLOAD_HOST", "c2")
PAYLOAD_PORT = os.environ.get("SIM_PAYLOAD_PORT", "8443")
PROXY_TOKEN = os.environ.get("SIM_PROXY_TOKEN", "proxytok")
RELAY_TOKEN = os.environ.get("SIM_RELAY_TOKEN", "relaytok")
REDIS_SSH_KEY = os.environ.get("SIM_REDIS_SSH_KEY", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMockTestKeyForNotnetRedisVector1234567890abcdefghijklmnopqrstuvwxyz notnet-test")

CONF_TPL = """# generated per-device notnet config (bot_tag=<id>)
http_server={http_server}
http_port={http_port}
http_path=/api/v1/bot
ws_server={ws_server}
ws_port={ws_port}
ws_enabled=1
c2_secret={secret}
heartbeat_interval=2
scan_interval=1
scan_timeout_ms=50
scan_max_hosts=254
ssh_enabled=1
telnet_enabled=1
smb_enabled=1
redis_enabled=1
rdp_enabled=1
persist_enabled=0
bot_tag={bot_tag}
proxy_token={proxy_token}
relay_token={relay_token}
redis_ssh_key={redis_ssh_key}
"""


def device_env(d):
    """Build the env dict for a device.py container."""
    env = {
        "DEVICE_ID": d["id"],
        "DEVICE_TYPE": d["type"],
        "DEVICE_PORTS": ",".join(str(p) for p in d.get("ports", [22])),
        "CVE": d.get("cve", "none"),
        "PATCHED": "true" if d.get("patched") else "false",
        "PATCHED_PARTIAL": "true" if d.get("patched_partial") else "false",
        "EDR_BLOCK": "true" if d.get("edr_block") else "false",
        "LOCKOUT": "true" if d.get("lockout") else "false",
        "SSH_KEY_ONLY": "true" if d.get("ssh_key_only") else "false",
        "SMB1_DISABLED": "true" if d.get("smb1_disabled") else "false",
        "STRONG_CREDS": "true" if d.get("strong_creds") else "false",
        "PAYLOAD_URL": f"http://{PAYLOAD_HOST}:{PAYLOAD_PORT}/bot/notnet",
        "EVIDENCE": f"/evidence/{d['id']}.log",
        "TELNET_CREDS": ",".join(d.get("telnet_creds", [])),
        "SSH_CREDS": ",".join(d.get("ssh_creds", [])),
        "SMB_CREDS": ",".join(d.get("smb_creds", [])),
        "REDIS_PASS": d.get("redis_pass", ""),
        "PERSIST": "true" if d.get("persist") else "false",
        "WEB_TITLE": d.get("web_title", ""),
    }
    return env


def build_compose(fleet):
    services = {}
    for d in fleet["devices"]:
        if d.get("type", "").startswith("honeypot"):
            # Cowrie honeypot: official image, telnet 2223 or ssh 2222
            if d.get("ports", []) == [22]:
                cowrie_port = 2222
                host_port = 22
            else:
                cowrie_port = 2223
                host_port = 23
            services[d["id"]] = {
                "image": "cowrie/cowrie:latest",
                "container_name": d["id"],
                "hostname": d["id"],
                "networks": {"simnet": {"ipv4_address": d["ip"]}},
                "expose": [f"{host_port}/tcp"],
                "volumes": [
                    f"./evidence:/cowrie/log:rw",
                    "./cowrie/cowrie.cfg:/cowrie/cowrie.cfg:ro",
                ],
                "environment": {
                    "COWRIE_TELNET_ENABLED": "true",
                    "COWRIE_SSH_ENABLED": "true",
                },
            }
            continue
        services[d["id"]] = {
            "image": "notnet-sim-device",
            "container_name": d["id"],
            "hostname": d["id"],
            "networks": {"simnet": {"ipv4_address": d["ip"]}},
            "environment": device_env(d),
            "volumes": ["./evidence:/evidence:rw"],
        }
    return {"services": services}


def write_confs(fleet):
    os.makedirs(OUT_CONF_DIR, exist_ok=True)
    for d in fleet["devices"]:
        if d.get("type", "").startswith("honeypot"):
            continue
        conf = CONF_TPL.format(
            http_server=HTTP_SERVER,
            http_port=HTTP_PORT,
            ws_server=WS_SERVER,
            ws_port=WS_PORT,
            secret=C2_SECRET,
            bot_tag=d["id"],
            proxy_token=PROXY_TOKEN,
            relay_token=RELAY_TOKEN,
            redis_ssh_key=REDIS_SSH_KEY,
        )
        with open(os.path.join(OUT_CONF_DIR, f"notnet-{d['id']}.conf"), "w") as f:
            f.write(conf)
    print(f"[gen_fleet] wrote {len(fleet['devices'])} device configs to {OUT_CONF_DIR}")


def main():
    with open(FLEET) as f:
        fleet = yaml.safe_load(f)
    compose = build_compose(fleet)
    with open(OUT_COMPOSE, "w") as f:
        yaml.safe_dump(compose, f, sort_keys=False)
    write_confs(fleet)
    print(f"[gen_fleet] wrote {OUT_COMPOSE}")
    print(f"[gen_fleet] devices: {[d['id'] for d in fleet['devices']]}")


if __name__ == "__main__":
    main()
