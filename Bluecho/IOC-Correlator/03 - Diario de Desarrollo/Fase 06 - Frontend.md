# Fase 06 — Frontend React

## Módulo 12 — Frontend base (completado)

### Qué se ha construido

Proyecto React 18 + Vite + TypeScript completamente configurado con:

| Fichero / carpeta | Propósito |
|---|---|
| `package.json` | Dependencias: React, TanStack Query, React Router, Recharts, Lucide |
| `vite.config.ts` | Alias `@/` → `src/`, proxy `/api` → backend |
| `tailwind.config.js` | Colores semánticos: `critical`, `malicious`, `suspicious`, `clean` |
| `src/index.css` | Directivas Tailwind + fondo oscuro global |
| `src/main.tsx` | Root: QueryClientProvider + BrowserRouter + App |
| `src/App.tsx` | Layout principal: header con nav, main, footer |
| `src/lib/utils.ts` | `cn()`, mapas de colores/labels por veredicto, `formatDate()` |
| `src/api/client.ts` | Todas las llamadas al backend tipadas en TypeScript |
| `src/components/SearchBar.tsx` | Input IOC + botón upload + drag & drop |
| `src/components/ThreatScore.tsx` | Gauge SVG con score 0-100 y color dinámico |
| `src/pages/Dashboard.tsx` | Página principal: SearchBar + ThreatScore + placeholder ResultsTable |
| `src/pages/History.tsx` | Tabla de historial con TanStack Query |

### Decisiones técnicas tomadas

**Proxy de Vite en desarrollo.**
`vite.config.ts` redirige `/api/*` al backend en `localhost:8000`. Esto evita problemas de CORS en desarrollo sin tocar la configuración del servidor. En producción, Nginx hace lo mismo.

**`VITE_API_BASE_URL` vacío por defecto.**
En desarrollo, el proxy de Vite intercepta `/api`. En producción (build estático servido por Nginx), la variable apunta a la URL real. Mismo código, dos entornos.

**Colores semánticos en Tailwind.**
`critical → rojo`, `malicious → naranja`, `suspicious → amarillo`, `clean → verde`. Se definen una vez en `tailwind.config.js` y se mapean desde `lib/utils.ts`. Ningún componente tiene los colores hardcodeados.

**Gauge SVG animado para el score.**
El `ThreatScore` usa un `<circle>` SVG con `strokeDasharray` calculado del score. La animación es CSS puro (`transition: stroke-dasharray 0.6s ease`), sin librería adicional.

**TanStack Query para el historial.**
El historial usa `useQuery` con `staleTime: 30s`. Las mutaciones de escaneo usan `useMutation`. Esto gestiona automáticamente el estado de carga, error y revalidación.

### Comandos para arrancar

```powershell
# Instalar dependencias (solo la primera vez)
cd frontend
npm install

# Arrancar en modo desarrollo
npm run dev
# → http://localhost:5173

# Build de producción
npm run build
# → dist/ listo para Nginx
```

### Prerrequisito

Node.js 22.x LTS instalado. Descargar de nodejs.org si no está disponible.

### Estado al terminar este módulo

- [x] Proyecto Vite configurado y listo para `npm install`
- [x] Tailwind con colores semánticos de amenaza
- [x] API client tipado con todos los endpoints del backend
- [x] `SearchBar` con input, upload y drag & drop
- [x] `ThreatScore` con gauge SVG animado
- [x] `Dashboard` funcional: muestra score + análisis IA tras escaneo
- [x] `History` con tabla paginada via TanStack Query
- [ ] `ResultsTable` y `AiSummary` como componentes dedicados → Módulo 13

---

## Módulo 13 — Frontend completo (completado)

### Qué se ha construido

| Componente | Propósito |
|---|---|
| `ResultsTable.tsx` | Tabla con una fila por conector: hallazgo clave, veredicto badge, puntos de scoring |
| `AiSummary.tsx` | Card con icono Sparkles y el texto del análisis IA |
| `HistoryList.tsx` | Lista compacta de escaneos recientes, clickable para recargar resultado |
| `SourcesStatus.tsx` | Pills de estado de cada conector (verde = activo, gris = sin API key) |
| `Dashboard.tsx` | Reescrito completo: layout en dos columnas, sidebar de historial en desktop |

### Layout del Dashboard (pantalla completa)

```
┌─────────────────────────────────┬──────────────────┐
│  SearchBar                       │                  │
│  SourcesStatus (pills)           │  SIDEBAR         │
│                                  │  Historial       │
│  ┌──────────┬──────────────────┐ │  reciente        │
│  │ThreatScore│ ResultsTable    │ │  (10 últimos)    │
│  │ (gauge)  │                  │ │                  │
│  └──────────┴──────────────────┘ │                  │
│  AiSummary (card azul)           │                  │
└─────────────────────────────────┴──────────────────┘
```

### Decisiones técnicas tomadas

**`KeyFinding` como componente interno de `ResultsTable`.** Cada conector tiene un campo "dato clave" diferente (motores VT, confianza AbuseIPDB, puertos Shodan...). En lugar de una función genérica, un switch por `source` extrae el dato relevante de `result.data` con tipos seguros.

**Puntos de scoring en la tabla.** La columna "Puntos" muestra `+30`, `-10`, etc. en rojo/verde según el signo. Esto hace visible de un vistazo qué fuente penaliza más el score.

**Sidebar oculto en móvil (`hidden lg:flex`).** El historial reciente solo aparece en pantallas grandes. En móvil, el historial está en la página `/history`.

**`queryClient.invalidateQueries` tras escaneo.** Cuando se completa un escaneo, se invalida la query `["history"]` para que el sidebar se actualice automáticamente sin recargar la página.

**`JSX.Element` en lugar de `React.ReactElement`.** Con el nuevo JSX transform de React 18 (sin `import React`), `JSX.Element` es el tipo global correcto para componentes función. `React.ReactElement` requiere importar React explícitamente.

### Comandos para arrancar (requiere Node.js instalado)

```powershell
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

### Estado al terminar esta fase

- [x] `ResultsTable` con hallazgo clave por conector y puntos de scoring
- [x] `AiSummary` con icono distintivo
- [x] `HistoryList` clickable que recarga el resultado en el panel
- [x] `SourcesStatus` con pills verde/gris por conector
- [x] Dashboard con layout de dos columnas y sidebar responsive
- [x] Loading state con spinner y mensaje durante el escaneo
- [x] Error state con banner rojo
- [x] Invalidación automática del historial tras cada escaneo
