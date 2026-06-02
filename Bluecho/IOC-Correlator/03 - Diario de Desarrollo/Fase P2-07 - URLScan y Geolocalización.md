# Fase P2-07 — URLScan.io y Geolocalización

## Qué se ha construido

Dos nuevas funcionalidades independientes: un conector para la API de URLScan.io que analiza URLs y dominios buscando indicadores de phishing y malware, y un sistema de geolocalización que muestra en un mapa interactivo la ubicación de IPs, dominios y URLs consultados.

---

## Conector URLScan.io

### Por qué URLScan.io

URLScan.io escanea URLs y dominios desde múltiples ubicaciones geográficas, captura pantallazos del sitio, analiza el DOM, detecta phishing y genera veredictos de maliciosidad. La API de búsqueda es **pública** (no requiere key) y devuelve resultados de escaneos previos, lo que evita crear nuevos escaneos públicos que expondrían la investigación.

### Implementación

```python
# connectors/urlscan.py
class URLScanConnector(BaseConnector):
    name = "urlscan"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    api_key_env = None  # API pública; key opcional para mayor cuota

    async def _fetch(self, ioc_value, ioc_type):
        query = f'page.url:"{ioc_value}"' if ioc_type == IOCType.URL else f"domain:{ioc_value}"
        resp = await client.get("https://urlscan.io/api/v1/search/", params={"q": query, "size": 5})
        return self._parse(resp.json())
```

Para cada escaneo encontrado se extrae: veredicto malicioso (bool), score (0-100), categorías detectadas (phishing, malware…), URL del screenshot y URL del informe completo.

### Scoring

| Condición | Puntos |
|---|---|
| Al menos un escaneo con veredicto malicioso | +30 |
| Score máximo > 50 sin veredicto malicioso | +15 |

### Variable de entorno

```
URLSCAN_API_KEY=   # opcional — aumenta el rate limit en urlscan.io
```

---

## Geolocalización de IOCs

### Qué se geolocaliza

| Tipo de IOC | Método |
|---|---|
| IPv4 / IPv6 | Consulta directa a ipwho.is |
| Dominio | Resolución DNS con `socket.gethostbyname()` → IP → ipwho.is |
| URL | Extracción del hostname con `urlparse` → resolución DNS → ipwho.is |
| Hash / PCAP | No aplicable — no se muestra el mapa |

### API utilizada: ipwho.is

API gratuita, sin key, HTTPS, con límite de 10.000 req/mes. Devuelve ciudad, región, país, coordenadas, ISP y organización.

```python
# geolocator.py
async def _geolocate_ip(ip: str) -> Optional[GeoLocation]:
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.get(f"https://ipwho.is/{ip}")
        data = resp.json()
        if not data.get("success"):
            return None
        return GeoLocation(lat=data["latitude"], lon=data["longitude"], ...)
```

La resolución DNS se ejecuta en un thread pool para no bloquear asyncio:

```python
ip = await asyncio.to_thread(socket.gethostbyname, domain)
```

### Integración en el flujo de escaneo

`geolocate()` se llama después de `_run_scan()` en los endpoints `/api/scan` y `/api/scan/json`. No se guarda en base de datos (se recalcula en cada consulta). El historial no muestra geolocalización.

```python
db_scan, breakdown = await _run_scan(ioc_value, session)
geo = await geolocate(ioc_value, db_scan.ioc_type)
return _build_scan_response(db_scan, breakdown, geolocation=geo)
```

### Schema

```python
class GeoLocation(BaseModel):
    lat: float
    lon: float
    city: str
    region: str
    country: str
    country_code: str
    org: Optional[str] = None
    resolved_ip: Optional[str] = None  # para dominios/URLs
```

### Componente GeoMap.tsx

Mapa Leaflet con `CircleMarker` (evita el problema de iconos en Vite) con tile de OpenStreetMap (sin API key):

```tsx
<MapContainer center={[geo.lat, geo.lon]} zoom={5}>
  <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
  <CircleMarker center={[geo.lat, geo.lon]} radius={10}
    pathOptions={{ color: "#3b82f6", fillColor: "#3b82f6", fillOpacity: 0.7 }}>
    <Popup>{iocValue}<br />{label}</Popup>
  </CircleMarker>
</MapContainer>
```

Se usa `CircleMarker` en lugar de `Marker` porque el icono por defecto de Leaflet requiere configuración adicional en Vite (las rutas de las imágenes se rompen durante el build).

### Comportamiento en el dashboard

- **Hay geolocalización:** se muestra el mapa con ciudad, región, país y organización. Si el IOC es un dominio o URL, también muestra la IP resuelta.
- **No hay geolocalización (fallo de API):** mensaje "No se ha podido determinar la geolocalización" — solo visible para IPs, dominios y URLs.
- **Hash u otro tipo:** el bloque no aparece.

### Dependencias añadidas

```json
"react-leaflet": "^4.2.1",
"leaflet": "^1.9.4",
"@types/leaflet": "^1.9.14"
```

---

## Estado al terminar esta fase

- [x] Conector URLScan.io para URL y dominio (API pública, sin key)
- [x] Scoring: +30 malicioso / +15 score > 50
- [x] `URLSCAN_API_KEY` como variable opcional en `.env.example`
- [x] Módulo `geolocator.py` con soporte IPv4, IPv6, dominio y URL
- [x] Resolución DNS async con `asyncio.to_thread`
- [x] Schema `GeoLocation` en `ScanResponse`
- [x] Componente `GeoMap.tsx` con Leaflet + OpenStreetMap
- [x] Mapa visible solo para tipos geolocalizables
- [x] Mensaje "no disponible" cuando la geolocalización falla
