"""
Mapeo estático de resultados de conectores a técnicas MITRE ATT&CK.
Los datos del framework son públicos: https://attack.mitre.org/
"""
from dataclasses import dataclass


@dataclass
class MitreTechnique:
    id: str       # e.g. "T1566.001"
    name: str     # e.g. "Spearphishing Attachment"
    tactic: str   # e.g. "Initial Access"
    url: str      # enlace a attack.mitre.org
    source: str   # conector que originó la atribución


# ---------------------------------------------------------------------------
# Catálogo de técnicas referenciadas
# ---------------------------------------------------------------------------

_T: dict[str, dict] = {
    # Initial Access
    "T1566.001": {"name": "Spearphishing Attachment",       "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link",              "tactic": "Initial Access"},
    "T1190":     {"name": "Exploit Public-Facing App",       "tactic": "Initial Access"},
    "T1133":     {"name": "External Remote Services",        "tactic": "Initial Access"},
    "T1078":     {"name": "Valid Accounts",                  "tactic": "Initial Access"},
    # Execution
    "T1059.001": {"name": "PowerShell",                      "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell",           "tactic": "Execution"},
    "T1059.005": {"name": "Visual Basic",                    "tactic": "Execution"},
    "T1204.002": {"name": "Malicious File",                  "tactic": "Execution"},
    # Persistence
    "T1547.001": {"name": "Registry Run Keys / Startup",     "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task",                  "tactic": "Persistence"},
    # Defense Evasion
    "T1055":     {"name": "Process Injection",               "tactic": "Defense Evasion"},
    "T1027":     {"name": "Obfuscated Files or Info",        "tactic": "Defense Evasion"},
    "T1036":     {"name": "Masquerading",                    "tactic": "Defense Evasion"},
    # Credential Access
    "T1110":     {"name": "Brute Force",                     "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing",               "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying",               "tactic": "Credential Access"},
    "T1003":     {"name": "OS Credential Dumping",           "tactic": "Credential Access"},
    "T1555":     {"name": "Credentials from Password Stores","tactic": "Credential Access"},
    # Discovery
    "T1046":     {"name": "Network Service Discovery",       "tactic": "Discovery"},
    "T1082":     {"name": "System Information Discovery",    "tactic": "Discovery"},
    "T1018":     {"name": "Remote System Discovery",         "tactic": "Discovery"},
    # Lateral Movement
    "T1021.001": {"name": "Remote Desktop Protocol",         "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB / Windows Admin Shares",      "tactic": "Lateral Movement"},
    "T1021.004": {"name": "SSH",                             "tactic": "Lateral Movement"},
    # Command and Control
    "T1071.001": {"name": "Web Protocols (HTTP/S)",          "tactic": "Command and Control"},
    "T1071.004": {"name": "DNS",                             "tactic": "Command and Control"},
    "T1095":     {"name": "Non-Application Layer Protocol",  "tactic": "Command and Control"},
    "T1090":     {"name": "Proxy",                           "tactic": "Command and Control"},
    "T1090.003": {"name": "Multi-hop Proxy (Tor)",           "tactic": "Command and Control"},
    "T1573":     {"name": "Encrypted Channel",               "tactic": "Command and Control"},
    "T1105":     {"name": "Ingress Tool Transfer",           "tactic": "Command and Control"},
    # Exfiltration
    "T1041":     {"name": "Exfiltration Over C2 Channel",    "tactic": "Exfiltration"},
    "T1048":     {"name": "Exfil Over Alternative Protocol", "tactic": "Exfiltration"},
    # Impact
    "T1486":     {"name": "Data Encrypted for Impact",       "tactic": "Impact"},
    "T1489":     {"name": "Service Stop",                    "tactic": "Impact"},
    "T1498":     {"name": "Network Denial of Service",       "tactic": "Impact"},
    "T1499":     {"name": "Endpoint Denial of Service",      "tactic": "Impact"},
    "T1496":     {"name": "Resource Hijacking (miner)",      "tactic": "Impact"},
}


def _build(tid: str, source: str) -> MitreTechnique:
    t = _T[tid]
    url_id = tid.replace(".", "/")
    return MitreTechnique(
        id=tid,
        name=t["name"],
        tactic=t["tactic"],
        url=f"https://attack.mitre.org/techniques/{url_id}/",
        source=source,
    )


# ---------------------------------------------------------------------------
# Mappings por fuente
# ---------------------------------------------------------------------------

# Familia de malware (minúsculas) → lista de TIDs
_MALWARE_MAP: dict[str, list[str]] = {
    # Loaders / Banking trojans
    "emotet":        ["T1566.001", "T1059.005", "T1071.001", "T1027", "T1547.001"],
    "qakbot":        ["T1566.001", "T1059.001", "T1055",     "T1071.001", "T1547.001"],
    "trickbot":      ["T1566.001", "T1059.001", "T1003",     "T1071.001", "T1021.002"],
    "dridex":        ["T1566.001", "T1059.001", "T1071.001", "T1027"],
    "icedid":        ["T1566.001", "T1059.001", "T1071.001", "T1027"],
    "ursnif":        ["T1566.001", "T1059.001", "T1055",     "T1071.001"],
    # RATs
    "asyncrat":      ["T1059.001", "T1071.001", "T1547.001", "T1082"],
    "remcos":        ["T1059.001", "T1071.001", "T1547.001", "T1082"],
    "njrat":         ["T1059.001", "T1071.001", "T1547.001", "T1082"],
    "nanocore":      ["T1059.001", "T1071.001", "T1547.001"],
    "quasar":        ["T1059.001", "T1071.001", "T1082",     "T1003"],
    "dcrat":         ["T1059.001", "T1071.001", "T1547.001"],
    "xworm":         ["T1059.001", "T1071.001", "T1547.001"],
    # Stealers
    "redline":       ["T1555",     "T1082",     "T1071.001", "T1027"],
    "raccoon":       ["T1555",     "T1082",     "T1071.001"],
    "vidar":         ["T1555",     "T1082",     "T1041"],
    # C2 frameworks
    "cobalt strike": ["T1059.001", "T1055",     "T1071.001", "T1573", "T1027", "T1036"],
    "cobaltstrike":  ["T1059.001", "T1055",     "T1071.001", "T1573", "T1027", "T1036"],
    "metasploit":    ["T1190",     "T1059.001", "T1055",     "T1071.001"],
    "brute ratel":   ["T1059.001", "T1055",     "T1071.001", "T1573"],
    "sliver":        ["T1059.001", "T1071.001", "T1573"],
    "havoc":         ["T1059.001", "T1071.001", "T1573"],
    # Ransomware
    "lockbit":       ["T1486", "T1021.002", "T1082", "T1078", "T1489"],
    "blackcat":      ["T1486", "T1021.002", "T1082", "T1078"],
    "alphv":         ["T1486", "T1021.002", "T1082", "T1078"],
    "conti":         ["T1486", "T1021.002", "T1003", "T1078"],
    "ryuk":          ["T1486", "T1021.002", "T1003"],
    "revil":         ["T1486", "T1078",     "T1082"],
    "sodinokibi":    ["T1486", "T1078",     "T1082"],
    "blackbasta":    ["T1486", "T1021.002", "T1082"],
    "cl0p":          ["T1190", "T1486",     "T1041"],
    "clop":          ["T1190", "T1486",     "T1041"],
    # Botnets / DDoS
    "mirai":         ["T1190", "T1110.001", "T1498", "T1499"],
    "mozi":          ["T1190", "T1110.001", "T1498"],
    # Miners
    "xmrig":         ["T1496", "T1190"],
}

# Puerto abierto → técnica ATT&CK
_PORT_MAP: dict[int, str] = {
    22:    "T1021.004",  # SSH
    23:    "T1021.004",  # Telnet → SSH (lateral movement)
    445:   "T1021.002",  # SMB
    3389:  "T1021.001",  # RDP
    1433:  "T1190",      # SQL Server
    4444:  "T1095",      # Metasploit default → non-app layer C2
    5900:  "T1021.001",  # VNC → RDP category
    6379:  "T1190",      # Redis sin auth
    27017: "T1190",      # MongoDB sin auth
}


# ---------------------------------------------------------------------------
# Función principal
# ---------------------------------------------------------------------------

def map_to_mitre(connector_results: dict) -> list[MitreTechnique]:
    """
    Recibe el dict de connector_results (clave=nombre, valor=dict con campos)
    y devuelve una lista deduplicada de MitreTechnique.
    """
    seen: set[str] = set()
    techniques: list[MitreTechnique] = []

    def add(tid: str, source: str) -> None:
        if tid in _T and tid not in seen:
            seen.add(tid)
            techniques.append(_build(tid, source))

    # -- ThreatFox: malware family -----------------------------------------
    tf = connector_results.get("threatfox", {})
    if tf.get("success") and tf.get("data", {}).get("found"):
        family = (tf["data"].get("malware") or "").lower().strip()
        for key, tids in _MALWARE_MAP.items():
            if key in family:
                for tid in tids:
                    add(tid, f"ThreatFox: {tf['data']['malware']}")
                break

    # -- Hybrid Analysis: vx_family ----------------------------------------
    ha = connector_results.get("hybrid_analysis", {})
    if ha.get("success") and ha.get("data", {}).get("vx_family"):
        family = ha["data"]["vx_family"].lower().strip()
        for key, tids in _MALWARE_MAP.items():
            if key in family:
                for tid in tids:
                    add(tid, f"Hybrid Analysis: {ha['data']['vx_family']}")
                break

    # -- IPinfo: privacy flags ---------------------------------------------
    ip = connector_results.get("ipinfo", {})
    if ip.get("success"):
        d = ip.get("data", {})
        if d.get("is_tor"):
            add("T1090.003", "IPinfo: Tor exit node")
        if d.get("is_vpn"):
            add("T1090", "IPinfo: VPN")
        if d.get("is_proxy"):
            add("T1090", "IPinfo: Proxy")

    # -- Shodan: puertos sensibles abiertos --------------------------------
    sh = connector_results.get("shodan", {})
    if sh.get("success"):
        for port in (sh.get("data", {}).get("open_ports") or []):
            tid = _PORT_MAP.get(int(port))
            if tid:
                add(tid, f"Shodan: puerto {port} abierto")

    # -- OTX: pulsos activos → C2 genérico ---------------------------------
    otx = connector_results.get("otx", {})
    if otx.get("success"):
        if (otx.get("data", {}).get("pulse_count") or 0) > 0:
            add("T1071.001", "AlienVault OTX: presente en pulsos activos")

    # -- Criminal IP: score alto → C2 + reconocimiento --------------------
    cip = connector_results.get("criminal_ip", {})
    if cip.get("success"):
        worst = (cip.get("data", {}).get("worst_score") or "").lower()
        if worst in ("critical", "dangerous"):
            add("T1071.001", "Criminal IP: score crítico/peligroso")
            add("T1046", "Criminal IP: score crítico/peligroso")

    return techniques
