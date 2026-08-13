// notnet static / file / memory indicator rules
// Matches distinctive, version-stable strings pulled from include/config.h and
// src/spread.c / src/relay.c. Run with: yara -r notnet_indicators.yar <file|dir|proc>

rule notnet_http_user_agent
{
    meta:
        description = "notnet HTTP/WS User-Agent (HTTP_USER_AGENT, include/config.h:50)"
        author = "notnet-detections"
        reference = "https://github.com/riceharvest/notnet"
        mitre_attack = "T1071.001"
    strings:
        $ua = "notnet/" ascii
    condition:
        $ua
}

rule notnet_relay_via_wireformat
{
    meta:
        description = "notnet ORB relay wire format RELAY <token> <target> <port> VIA <hop> (src/relay.c, config.h #91)"
        author = "notnet-detections"
        reference = "https://github.com/riceharvest/notnet"
        mitre_attack = "T1090"
    strings:
        $relay = "RELAY " ascii
        $via   = " VIA " ascii
    condition:
        $relay and $via
}

rule notnet_cve_module_strings
{
    meta:
        description = "notnet CVE module dispatch strings (cve_modules[] in src/spread.c)"
        author = "notnet-detections"
        reference = "https://github.com/riceharvest/notnet"
        mitre_attack = "T1190"
    strings:
        $c1 = "CVE-2017-17215" ascii
        $c2 = "CVE-2021-35395" ascii
        $c3 = "CVE-2024-3721" ascii
        $hg  = "HG532" ascii
        $form = "formSysCmd" ascii
    condition:
        any of ($c1, $c2, $c3, $hg, $form)
}

rule notnet_killswitch_markers
{
    meta:
        description = "notnet global DNS killswitch markers (include/config.h #130)"
        author = "notnet-detections"
        reference = "https://github.com/riceharvest/notnet"
        mitre_attack = "T1489"
    strings:
        $ks  = "killswitch.invalid" ascii
        $ksd = "KILLSWITCH_DOMAIN" ascii
    condition:
        any of them
}

rule notnet_broadcast_bc
{
    meta:
        description = "notnet bc- broadcast payload filename convention (c2-server README)"
        author = "notnet-detections"
        reference = "https://github.com/riceharvest/notnet"
        mitre_attack = "T1105"
    strings:
        $bc = "bc-" ascii
    condition:
        $bc
}

rule notnet_cred_log_format
{
    meta:
        description = "notnet credential harvest buffer layout proto|ip|port|user|pass (README Credential log)"
        author = "notnet-detections"
        reference = "https://github.com/riceharvest/notnet"
        mitre_attack = "T1003"
    strings:
        $fmt = "|ip|port|user|pass" ascii
    condition:
        $fmt
}

rule notnet_fileless_memfd_fexecve
{
    meta:
        description = "notnet RAM-only fileless mode via memfd_create + fexecve (README RAM-only fileless mode)"
        author = "notnet-detections"
        reference = "https://github.com/riceharvest/notnet"
        mitre_attack = "T1027.011"
    strings:
        $m = "memfd_create" ascii
        $f = "fexecve" ascii
    condition:
        $m and $f
}

rule notnet_magic_header
{
    meta:
        description = "notnet magic header NOTN (NOTNET_MAGIC 0x4E4F544E, include/config.h:13)"
        author = "notnet-detections"
        reference = "https://github.com/riceharvest/notnet"
        mitre_attack = "T1027"
    strings:
        $magic = { 4E 4F 54 4E }   // "NOTN"
    condition:
        $magic
}
