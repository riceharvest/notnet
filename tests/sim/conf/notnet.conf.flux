# notnet sim — flux-only resilience config (no dead-drop, so flux-c2 is used)
flux_enabled=1
flux_ttl=2
http_server=flux-c2
http_port=8080
http_path=/api/v1/bot
c2_secret=mocksecret
heartbeat_interval=2
scan_interval=30
scan_timeout_ms=50
scan_max_hosts=254
persist_enabled=0
bot_tag=sim-flux-1
