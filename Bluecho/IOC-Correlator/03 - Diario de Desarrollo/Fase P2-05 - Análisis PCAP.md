# Fase P2-05 — Análisis de Capturas de Red (PCAP/PCAPNG)

## Qué se ha construido

Soporte completo para analizar ficheros de captura de red. El usuario sube un `.pcap` o `.pcapng`, el backend lo parsea con scapy, extrae IOCs y estadísticas de tráfico, y la IA genera un informe forense específico para tráfico de red.

---

## Backend: pcap_analyzer.py

### Detección de formato

La detección se hace por magic bytes, no por extensión de fichero, para evitar spoofing:

| Magic bytes | Formato |
|---|---|
| `\xd4\xc3\xb2\xa1` / `\xa1\xb2\xc3\xd4` | pcap LE/BE |
| `\x4d\x3c\xb2\xa1` / `\xa1\xb2\x3c\x4d` | pcap nanosegundo |
| `\x0a\x0d\x0d\x0a` | pcapng |

### Parseo con scapy (en thread pool)

scapy es CPU-bound. Ejecutarlo directamente en una función `async` bloquearía el event loop de asyncio y dejaría el servidor sin responder a otras peticiones durante el parseo.

**Solución:** `asyncio.to_thread()` ejecuta el parseo en el thread pool del sistema operativo:

```python
async def analyze_pcap(content: bytes) -> tuple[list, dict]:
    with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
        f.write(content)
        tmp_path = f.name
    return await asyncio.to_thread(_parse_pcap_sync, tmp_path)
```

El fichero temporal se escribe antes de llamar a `to_thread` porque scapy necesita una ruta de fichero, no un buffer en memoria.

### Información extraída por paquete

Para cada paquete se extrae:
- **IP origen y destino** (IPv4 e IPv6)
- **Conteo de conexiones** por tupla (src_ip, src_port, dst_ip, dst_port)
- **HTTP:** cabecera `Host:` de peticiones GET/POST/HEAD
- **TLS:** SNI (Server Name Indication) del ClientHello
- **DNS:** nombre de dominio de las queries DNSQR

### Extracción del SNI en TLS

El SNI está en la extensión tipo 0 del ClientHello de TLS. La extracción se hace parseando los bytes del payload TCP directamente, sin necesidad de descifrar el tráfico:

```
TLS record (5 bytes): type=0x16, version, length
Handshake header (4 bytes): type=0x01 (ClientHello), length
ClientHello body:
  client_version (2) + random (32) + session_id_len (1) + session_id
  cipher_suites_len (2) + cipher_suites
  compression_methods_len (1) + compression_methods
  extensions_len (2) + extensions...
    Extension type=0x0000 (SNI):
      list_len (2) + name_type (1) + name_len (2) + hostname
```

### Límite de paquetes

Por seguridad se procesa un máximo de 50.000 paquetes por fichero (`MAX_PACKETS = 50_000`). Un PCAP típico de malware-traffic-analysis.net tiene entre 1.000 y 10.000 paquetes.

---

## Nuevo endpoint: POST /api/scan/pcap

```
POST /api/scan/pcap
Content-Type: multipart/form-data
X-API-Key: <key>

file: <pcap_file>
```

Respuesta `PcapScanResponse`:

```json
{
  "filename": "2024-01-15-traffic.pcap",
  "ai_summary": "## Resumen del tráfico\n...",
  "iocs_found": [
    {"value": "185.220.101.45", "ioc_type": "ipv4"},
    {"value": "evil-domain.ru", "ioc_type": "domain"}
  ],
  "total_iocs": 23,
  "stats": {
    "total_packets": 4821,
    "total_bytes": 2847392,
    "protocols": {"TCP": 3940, "UDP": 881},
    "top_connections": [...],
    "dns_queries": [...],
    "http_hosts": [...],
    "tls_sni": [...]
  }
}
```

El endpoint `/api/scan` existente rechaza PCAPs con un error descriptivo para evitar confusión.

---

## IA: prompt forense de tráfico de red

System prompt diferente al de análisis de IOCs individuales. Posiciona al modelo como analista forense de red en lugar de analista de Threat Intelligence:

```
## Resumen del tráfico
Volumen, protocolos dominantes, perfil general.

## Indicadores sospechosos
IPs/dominios con motivo concreto: alto volumen, puerto inusual,
dominio DGA, patrón de beacon, tráfico no cifrado sensible.

## Vector de ataque probable
C2 callback, exfiltración, lateral movement, escaneo, dropper...

## Recomendaciones de respuesta
3-5 acciones inmediatas ordenadas por prioridad.
```

El user prompt incluye todos los datos estadísticos: total de paquetes, distribución de protocolos, top 10 conexiones, lista de queries DNS, hosts HTTP y nombres TLS.

---

## Frontend: PcapAnalysisView

Componente nuevo con cuatro bloques:

1. **Cabecera** — nombre del fichero, total de paquetes, KB y número de IOCs extraídos.
2. **Distribución de protocolos** — cards con conteo por protocolo (TCP, UDP, OTHER).
3. **Análisis IA** — mismo diseño que `AiSummary` con renderizado Markdown.
4. **Tabla de conexiones** — top 15 conexiones por volumen de paquetes.
5. **Listas DNS/HTTP/SNI** — columnas con los dominios e hosts identificados.
6. **IOCs extraídos** — badges con código de color por tipo (IPs en naranja, dominios en azul, hashes en morado).

### Detección automática en SearchBar

El componente `SearchBar` detecta la extensión del fichero y enruta automáticamente:

```typescript
function handleFile(file: File | undefined) {
  if (!file) return;
  if (/\.pcap(ng)?$/i.test(file.name)) {
    onScanPcap(file);   // → POST /api/scan/pcap
  } else {
    onScanFile(file);   // → POST /api/scan
  }
}
```

El selector de fichero acepta `.log`, `.txt`, `.csv`, `.json`, `.pcap` y `.pcapng`.

---

## Estado al terminar esta fase

- [x] Detección de PCAP por magic bytes
- [x] Parseo con scapy en thread pool (no bloquea asyncio)
- [x] Extracción de IPs, DNS, HTTP hosts y TLS SNI
- [x] Extracción de SNI sin descifrar tráfico TLS
- [x] Endpoint `/api/scan/pcap` con schemas propios
- [x] Prompt forense específico para tráfico de red
- [x] Fallback Groq → Anthropic → análisis local para PCAP
- [x] Componente `PcapAnalysisView` con tabla de conexiones y listas
- [x] Detección automática de PCAP en SearchBar por extensión
