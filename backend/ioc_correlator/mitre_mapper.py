"""
Mapeo estático de resultados de conectores a técnicas MITRE ATT&CK.
Los datos del framework son públicos: https://attack.mitre.org/
"""
from dataclasses import dataclass


@dataclass
class MitreTechnique:
    id: str           # e.g. "T1566.001"
    name: str         # e.g. "Spearphishing Attachment"
    tactic: str       # e.g. "Initial Access"
    url: str          # enlace a attack.mitre.org
    source: str       # conector que originó la atribución
    reason: str = ""  # por qué se activó esta técnica (evidencia concreta)
    description: str = ""  # qué consiste la técnica (resumen breve)


# ---------------------------------------------------------------------------
# Catálogo de técnicas referenciadas
# ---------------------------------------------------------------------------

_T: dict[str, dict] = {
    # Initial Access
    "T1566.001": {"name": "Spearphishing Attachment",        "tactic": "Initial Access",
                  "description": "El adversario envía correos con adjuntos maliciosos para comprometer el sistema del receptor cuando abre el fichero."},
    "T1566.002": {"name": "Spearphishing Link",               "tactic": "Initial Access",
                  "description": "El adversario envía correos con enlaces a recursos maliciosos que descargan malware o capturan credenciales."},
    "T1190":     {"name": "Exploit Public-Facing App",        "tactic": "Initial Access",
                  "description": "El adversario explota vulnerabilidades en servicios expuestos a internet (webs, VPN, bases de datos) para obtener acceso inicial."},
    "T1133":     {"name": "External Remote Services",         "tactic": "Initial Access",
                  "description": "El adversario usa servicios de acceso remoto legítimos (VPN, RDP, Citrix) con credenciales comprometidas para acceder a la red."},
    "T1078":     {"name": "Valid Accounts",                   "tactic": "Initial Access",
                  "description": "El adversario usa credenciales legítimas (robadas o por defecto) para autenticarse en sistemas y evadir detección."},
    # Execution
    "T1059.001": {"name": "PowerShell",                       "tactic": "Execution",
                  "description": "El adversario usa PowerShell para ejecutar comandos, descargar payloads y moverse lateralmente, aprovechando que es una herramienta legítima del sistema."},
    "T1059.003": {"name": "Windows Command Shell",            "tactic": "Execution",
                  "description": "El adversario usa cmd.exe para ejecutar comandos, scripts y binarios maliciosos en el sistema comprometido."},
    "T1059.005": {"name": "Visual Basic",                     "tactic": "Execution",
                  "description": "El adversario usa scripts VBScript o macros VBA en documentos Office para ejecutar código malicioso cuando el usuario abre el fichero."},
    "T1204.002": {"name": "Malicious File",                   "tactic": "Execution",
                  "description": "El adversario engaña al usuario para que abra o ejecute un fichero malicioso (ejecutable, documento con macro, archivo LNK)."},
    # Persistence
    "T1547.001": {"name": "Registry Run Keys / Startup",      "tactic": "Persistence",
                  "description": "El adversario añade entradas en claves de registro o carpetas de inicio para ejecutar malware automáticamente en cada arranque del sistema."},
    "T1053.005": {"name": "Scheduled Task",                   "tactic": "Persistence",
                  "description": "El adversario crea tareas programadas para ejecutar malware periódicamente o tras eventos del sistema, garantizando persistencia."},
    # Defense Evasion
    "T1055":     {"name": "Process Injection",                "tactic": "Defense Evasion",
                  "description": "El adversario inyecta código malicioso en procesos legítimos (explorer.exe, svchost.exe) para ocultar su actividad y evadir soluciones de seguridad."},
    "T1027":     {"name": "Obfuscated Files or Info",         "tactic": "Defense Evasion",
                  "description": "El adversario ofusca código, strings o payloads (Base64, XOR, compresión) para dificultar el análisis estático y evadir detección antivirus."},
    "T1036":     {"name": "Masquerading",                     "tactic": "Defense Evasion",
                  "description": "El adversario disfraza malware con nombres o iconos de programas legítimos para engañar a usuarios y soluciones de seguridad."},
    # Credential Access
    "T1110":     {"name": "Brute Force",                      "tactic": "Credential Access",
                  "description": "El adversario intenta múltiples combinaciones de credenciales de forma sistemática para acceder a cuentas o sistemas."},
    "T1110.001": {"name": "Password Guessing",                "tactic": "Credential Access",
                  "description": "El adversario prueba contraseñas comunes o predecibles contra cuentas conocidas, aprovechando políticas de bloqueo débiles."},
    "T1110.003": {"name": "Password Spraying",                "tactic": "Credential Access",
                  "description": "El adversario prueba una misma contraseña contra muchas cuentas para evitar bloqueos por intentos fallidos en una sola cuenta."},
    "T1003":     {"name": "OS Credential Dumping",            "tactic": "Credential Access",
                  "description": "El adversario extrae credenciales almacenadas en memoria (LSASS), SAM o NTDS.dit para usarlas en movimiento lateral o acceso persistente."},
    "T1555":     {"name": "Credentials from Password Stores", "tactic": "Credential Access",
                  "description": "El adversario roba credenciales guardadas en gestores de contraseñas, navegadores o keystores del sistema operativo."},
    # Discovery
    "T1046":     {"name": "Network Service Discovery",        "tactic": "Discovery",
                  "description": "El adversario escanea la red para descubrir hosts activos y servicios expuestos, generalmente con herramientas como nmap o masscan."},
    "T1082":     {"name": "System Information Discovery",     "tactic": "Discovery",
                  "description": "El adversario recopila información del sistema comprometido (OS, versión, hardware) para planificar fases posteriores del ataque."},
    "T1018":     {"name": "Remote System Discovery",          "tactic": "Discovery",
                  "description": "El adversario enumera otros sistemas en la red (ARP, NetBIOS, AD queries) para identificar objetivos de movimiento lateral."},
    # Lateral Movement
    "T1021.001": {"name": "Remote Desktop Protocol",          "tactic": "Lateral Movement",
                  "description": "El adversario usa RDP (puerto 3389) con credenciales válidas para acceder interactivamente a otros sistemas de la red."},
    "T1021.002": {"name": "SMB / Windows Admin Shares",       "tactic": "Lateral Movement",
                  "description": "El adversario usa SMB y shares administrativos (C$, ADMIN$) para transferir ficheros y ejecutar código en sistemas remotos."},
    "T1021.004": {"name": "SSH",                              "tactic": "Lateral Movement",
                  "description": "El adversario usa SSH con credenciales comprometidas o claves robadas para acceder a sistemas Unix/Linux de la red."},
    # Command and Control
    "T1071.001": {"name": "Web Protocols (HTTP/S)",           "tactic": "Command and Control",
                  "description": "El adversario usa HTTP o HTTPS para comunicarse con su infraestructura C2, mezclando el tráfico malicioso con navegación web legítima."},
    "T1071.004": {"name": "DNS",                              "tactic": "Command and Control",
                  "description": "El adversario usa consultas DNS para exfiltrar datos o recibir instrucciones C2, aprovechando que el tráfico DNS raramente se bloquea."},
    "T1095":     {"name": "Non-Application Layer Protocol",   "tactic": "Command and Control",
                  "description": "El adversario usa protocolos de capa de red o transporte (ICMP, raw TCP/UDP) para comunicaciones C2 que evaden inspección de capa de aplicación."},
    "T1090":     {"name": "Proxy",                            "tactic": "Command and Control",
                  "description": "El adversario usa proxies para ocultar la dirección real del servidor C2 y dificultar el rastreo de su infraestructura."},
    "T1090.003": {"name": "Multi-hop Proxy (Tor)",            "tactic": "Command and Control",
                  "description": "El adversario enruta el tráfico C2 a través de la red Tor o cadenas de proxies para anonimizar su infraestructura y dificultar el bloqueo."},
    "T1573":     {"name": "Encrypted Channel",                "tactic": "Command and Control",
                  "description": "El adversario cifra las comunicaciones C2 con protocolos propios o estándar (TLS, SSH) para impedir la inspección del tráfico."},
    "T1105":     {"name": "Ingress Tool Transfer",            "tactic": "Command and Control",
                  "description": "El adversario descarga herramientas o payloads adicionales desde internet al sistema comprometido para ampliar sus capacidades."},
    # Exfiltration
    "T1041":     {"name": "Exfiltration Over C2 Channel",     "tactic": "Exfiltration",
                  "description": "El adversario exfiltra datos usando el mismo canal C2 ya establecido, reduciendo el número de conexiones salientes anómalas."},
    "T1048":     {"name": "Exfil Over Alternative Protocol",  "tactic": "Exfiltration",
                  "description": "El adversario usa protocolos alternativos (DNS, ICMP, SMTP, FTP) para exfiltrar datos y evadir controles de DLP sobre HTTP/S."},
    # Impact
    "T1486":     {"name": "Data Encrypted for Impact",        "tactic": "Impact",
                  "description": "El adversario cifra ficheros del sistema o de usuario (ransomware) para interrumpir operaciones y exigir rescate."},
    "T1489":     {"name": "Service Stop",                     "tactic": "Impact",
                  "description": "El adversario detiene servicios críticos (antivirus, backups, bases de datos) para facilitar el ataque o maximizar el impacto."},
    "T1498":     {"name": "Network Denial of Service",        "tactic": "Impact",
                  "description": "El adversario satura la red objetivo con tráfico masivo (DDoS volumétrico) para hacer inaccesibles los servicios."},
    "T1499":     {"name": "Endpoint Denial of Service",       "tactic": "Impact",
                  "description": "El adversario agota recursos del sistema (CPU, memoria, conexiones) para degradar o inutilizar servicios específicos."},
    "T1496":     {"name": "Resource Hijacking (miner)",       "tactic": "Impact",
                  "description": "El adversario usa los recursos computacionales del sistema comprometido (CPU/GPU) para minar criptomonedas en su beneficio."},
}


def _build(tid: str, source: str, reason: str = "") -> MitreTechnique:
    t = _T[tid]
    url_id = tid.replace(".", "/")
    return MitreTechnique(
        id=tid,
        name=t["name"],
        tactic=t["tactic"],
        url=f"https://attack.mitre.org/techniques/{url_id}/",
        source=source,
        reason=reason,
        description=t.get("description", ""),
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

    def add(tid: str, source: str, reason: str = "") -> None:
        if tid in _T and tid not in seen:
            seen.add(tid)
            techniques.append(_build(tid, source, reason))

    # -- ThreatFox: malware family -----------------------------------------
    tf = connector_results.get("threatfox", {})
    if tf.get("success") and tf.get("data", {}).get("found"):
        family_name = tf["data"].get("malware") or ""
        family = family_name.lower().strip()
        for key, tids in _MALWARE_MAP.items():
            if key in family:
                for tid in tids:
                    add(tid, f"ThreatFox",
                        f"ThreatFox identifica el IOC como infraestructura de {family_name}.")
                break

    # -- Hybrid Analysis: vx_family ----------------------------------------
    ha = connector_results.get("hybrid_analysis", {})
    if ha.get("success") and ha.get("data", {}).get("vx_family"):
        family_name = ha["data"]["vx_family"]
        family = family_name.lower().strip()
        for key, tids in _MALWARE_MAP.items():
            if key in family:
                for tid in tids:
                    add(tid, "Hybrid Analysis",
                        f"El sandbox de Hybrid Analysis clasificó la muestra como {family_name}.")
                break

    # -- IPinfo: privacy flags ---------------------------------------------
    ip = connector_results.get("ipinfo", {})
    if ip.get("success"):
        d = ip.get("data", {})
        if d.get("is_tor"):
            add("T1090.003", "IPinfo",
                "IPinfo confirma que esta IP es un nodo de salida de la red Tor, usada para anonimizar el origen del tráfico C2.")
        if d.get("is_vpn"):
            add("T1090", "IPinfo",
                "IPinfo identifica esta IP como perteneciente a un proveedor VPN, lo que puede indicar uso como proxy para ocultar el origen real.")
        if d.get("is_proxy"):
            add("T1090", "IPinfo",
                "IPinfo identifica esta IP como un proxy público, técnica común para enmascarar la infraestructura C2.")

    # -- Shodan: puertos sensibles abiertos --------------------------------
    sh = connector_results.get("shodan", {})
    if sh.get("success"):
        port_reasons = {
            22:    "Shodan detecta el puerto 22 (SSH) abierto, protocolo usado habitualmente para movimiento lateral en entornos Linux.",
            23:    "Shodan detecta el puerto 23 (Telnet) abierto, protocolo sin cifrado asociado a dispositivos IoT comprometidos.",
            445:   "Shodan detecta el puerto 445 (SMB) abierto, vector frecuente de movimiento lateral y propagación de ransomware.",
            3389:  "Shodan detecta el puerto 3389 (RDP) abierto, objetivo habitual de ataques de fuerza bruta y movimiento lateral.",
            1433:  "Shodan detecta el puerto 1433 (SQL Server) abierto, potencial vector de explotación de bases de datos expuestas.",
            4444:  "Shodan detecta el puerto 4444 abierto, puerto por defecto de Metasploit y otros frameworks C2.",
            5900:  "Shodan detecta el puerto 5900 (VNC) abierto, servicio de escritorio remoto a menudo sin autenticación.",
            6379:  "Shodan detecta el puerto 6379 (Redis) abierto, base de datos frecuentemente expuesta sin contraseña.",
            27017: "Shodan detecta el puerto 27017 (MongoDB) abierto, base de datos frecuentemente expuesta sin autenticación.",
        }
        for port in (sh.get("data", {}).get("open_ports") or []):
            port_int = int(port)
            tid = _PORT_MAP.get(port_int)
            if tid:
                reason = port_reasons.get(port_int, f"Shodan detecta el puerto {port} abierto, asociado a esta técnica de movimiento lateral o C2.")
                add(tid, "Shodan", reason)

    # -- OTX: pulsos activos → C2 genérico ---------------------------------
    otx = connector_results.get("otx", {})
    if otx.get("success"):
        pulse_count = otx.get("data", {}).get("pulse_count") or 0
        if pulse_count > 0:
            add("T1071.001", "AlienVault OTX",
                f"AlienVault OTX referencia este IOC en {pulse_count} pulso(s) de amenaza activos, indicando uso en campañas de malware que emplean HTTP/S como canal C2.")

    # -- Criminal IP: score alto → C2 + reconocimiento --------------------
    cip = connector_results.get("criminal_ip", {})
    if cip.get("success"):
        worst = (cip.get("data", {}).get("worst_score") or "").lower()
        if worst in ("critical", "dangerous"):
            add("T1071.001", "Criminal IP",
                f"Criminal IP asigna un score {worst} a esta IP, perfil consistente con servidores C2 que usan protocolos web para el mando y control.")
            add("T1046", "Criminal IP",
                f"Una IP con score {worst} en Criminal IP sugiere actividad de reconocimiento o escaneo masivo de servicios de red.")

    return techniques
