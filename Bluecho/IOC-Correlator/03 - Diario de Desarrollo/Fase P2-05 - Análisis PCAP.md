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

## Historial PCAP completo

### Problema

Al guardar un escaneo PCAP en la base de datos, solo se almacenaba un resumen mínimo (total de paquetes, número de IOCs). Al acceder al detalle desde el historial, no había forma de reconstruir la vista completa con IOCs, estadísticas y objetos extraídos.

### Solución: almacenar datos completos en connector_results

El campo `connector_results` (JSON) se usa para guardar todos los datos del análisis bajo la clave especial `__pcap_data__`:

```python
connector_results={
    "pcap_analyzer": { ...resumen mínimo para la tabla de fuentes... },
    "__pcap_data__": {
        "iocs_found": [...],       # lista completa de IOCs
        "stats": {...},            # estadísticas completas de tráfico
        "extracted_objects": [...] # objetos HTTP extraídos (con data_b64)
    }
}
```

### Nuevo endpoint

```
GET /api/history/{id}/pcap
→ PcapScanResponse reconstruido desde __pcap_data__
```

FastAPI necesita que las rutas más específicas (`/history/{id}/pcap`) estén declaradas **antes** que las genéricas (`/history/{id}`) para evitar que el parámetro `{id}` capture el literal `pcap`.

### Frontend: ScanDetail con detección de tipo

`ScanDetail.tsx` hace dos consultas en serie:
1. `getScanById(id)` → datos básicos + `ioc_type`
2. Si `ioc_type === "pcap"` → `getPcapScanById(id)` y renderiza `PcapAnalysisView`

Si el PCAP fue escaneado antes de esta mejora (sin `__pcap_data__`), se muestra un mensaje indicando que hay que volver a analizarlo.

### Filtro y sidebar

- **History.tsx:** añadido chip de filtro "PCAP" en la lista de tipos de IOC.
- **Dashboard.tsx:** `handleHistorySelect` detecta `ioc_type === "pcap"` y llama a `getPcapScanById`, asignando el resultado a `pcapResult` en lugar de `result` para que se renderice `PcapAnalysisView`.

---

## Persistencia en historial

El endpoint `/api/scan/pcap` no guardaba el resultado en base de datos. Corregido añadiendo `session: Session = Depends(get_session)` al endpoint y llamando a `save_scan()`:

```python
save_scan(
    session,
    ioc_value=filename,        # nombre del fichero como identificador
    ioc_type="pcap",
    score=0,
    verdict="clean",
    connector_results={"pcap_analyzer": {...}},
    ai_summary=ai_summary,
)
```

El historial muestra el nombre del fichero y `ioc_type="pcap"` para distinguirlo de escaneos de IOCs individuales.

---

## IOCs clicables en PcapAnalysisView

Los badges de IOC extraídos son ahora botones. Al hacer clic en uno, se lanza un escaneo completo de Threat Intelligence sobre ese IOC:

```typescript
// PcapAnalysisView recibe un callback opcional
interface Props {
  result: PcapScanResponse;
  onScanIoc?: (ioc: string) => void;
}

// Badge → button con onClick
<button onClick={() => onScanIoc?.(ioc.value)} ...>
```

En Dashboard.tsx:
```tsx
<PcapAnalysisView
  result={pcapResult}
  onScanIoc={(ioc) => mutation.mutate({ ioc })}
/>
```

Al hacer clic, el `mutation.onSuccess` limpia `pcapResult` y muestra el resultado de TI del IOC seleccionado.

---

## Extracción de objetos HTTP del tráfico

El módulo `pcap_analyzer.py` rensambla los streams TCP y extrae ficheros transferidos por HTTP sin cifrar.

### Reensamblado de streams TCP

```python
tcp_streams: dict = defaultdict(bytearray)
# Por cada paquete TCP con payload:
stream_key = (src, sport, dst, dport)
tcp_streams[stream_key] += payload
```

Los payloads se acumulan en orden de captura (suficiente para la mayoría de PCAPs de análisis de malware).

### Detección por magic bytes

| Magic | Extensión | Sospechoso |
|---|---|---|
| `\x4d\x5a` | exe | Sí — Windows PE |
| `\x7fELF` | elf | Sí — Linux ELF |
| `PK\x03\x04` | zip | Sí — ZIP/JAR/DOCX |
| `\xd0\xcf\x11\xe0` | doc | Sí — OLE2/MSI |
| `Rar!` | rar | Sí |
| `%PDF` | pdf | No |

Los tipos aburridos (HTML, CSS, JS, imágenes) se descartan salvo que los magic bytes digan lo contrario.

### Límites de seguridad

- Máximo 10 objetos por PCAP
- Máximo 5 MB por objeto
- Solo respuestas HTTP 200 y 206

### Transporte y descarga

Los objetos se devuelven como base64 en `PcapScanResponse.extracted_objects`. El frontend los decodifica en el navegador con `atob()` y genera un blob descargable.

### Modal de aviso antes de descargar

Antes de iniciar la descarga se muestra un modal con los metadatos del fichero y un aviso explícito de que puede contener malware. El botón de confirmación requiere acción deliberada del usuario.

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
- [x] Persistencia de escaneos PCAP en historial
- [x] IOCs extraídos clicables → lanza escaneo TI del IOC
- [x] Extracción de objetos HTTP con detección por magic bytes
- [x] Reensamblado de streams TCP
- [x] Modal de aviso antes de descarga de objetos potencialmente maliciosos
- [x] Historial PCAP completo — datos completos recuperables desde la BD
- [x] Endpoint `/api/history/{id}/pcap` para recuperar `PcapScanResponse`
- [x] `ScanDetail.tsx` detecta PCAP y renderiza `PcapAnalysisView`
- [x] Filtro "PCAP" en la página de historial
- [x] Sidebar del Dashboard enruta PCAPs a `pcapResult`
