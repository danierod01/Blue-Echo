# Fase P2-03 — Bulk Scan y Exportación CSV

## Qué se ha construido

Panel de escaneo masivo que permite analizar listas de IOCs en serie, con seguimiento de progreso en tiempo real y exportación de resultados a CSV.

---

## Componente BulkScanPanel

Nuevo componente `frontend/src/components/BulkScanPanel.tsx` accesible desde el toggle "Masivo" en el dashboard.

### Flujo de uso

1. El usuario pega una lista de IOCs en el textarea (uno por línea) o sube un fichero de logs.
2. El panel extrae los IOCs únicos (eliminando duplicados y líneas vacías), hasta un máximo de 50.
3. Para cada IOC, llama secuencialmente a `POST /api/scan/json` con un delay de 1,5 segundos entre peticiones.
4. Muestra una barra de progreso y el estado de cada IOC (pendiente, escaneando, completado, error).
5. Al terminar, el botón "Exportar CSV" genera y descarga el fichero con todos los resultados.

### Por qué secuencial y no paralelo

Las APIs gratuitas de Threat Intelligence tienen rate limits estrictos, especialmente VirusTotal (4 req/min). Lanzar 50 peticiones en paralelo agotaría el rate limit en segundos y dejaría el resto de IOCs sin datos de la fuente más importante. El procesamiento secuencial con delay controlado es más lento pero produce resultados completos.

```typescript
for (const ioc of iocs) {
  await new Promise(r => setTimeout(r, 1500));
  const result = await scanIoc(ioc);
  // actualizar estado
}
```

---

## Exportación CSV

### Formato del fichero

```csv
IOC,Tipo,Score,Veredicto,VirusTotal,AbuseIPDB,Shodan,OTX,...,Fecha
185.220.101.45,ipv4,87,critical,15,40,20,20,...,2026-05-20T14:32:08
```

Una columna por conector con su contribución al score. El veredicto final y el score total en columnas separadas.

### CSV injection protection

Los valores que empiezan por `=`, `-`, `+` o `@` se prefijan con un tabulador antes de escribirlos en el CSV. Sin esta protección, un IOC como `=cmd|' /C calc'!A0` podría ejecutar código en Excel al abrir el fichero.

```typescript
const sanitize = (cell: string) =>
  /^[=\-+@]/.test(cell) ? `\t${cell}` : cell;
```

---

## Estado al terminar esta fase

- [x] Panel masivo con textarea y carga de fichero
- [x] Barra de progreso en tiempo real
- [x] Delay entre peticiones para respetar rate limits
- [x] Exportación CSV con protección contra CSV injection
- [x] Toggle Individual/Masivo en el dashboard principal
