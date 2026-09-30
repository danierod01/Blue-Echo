import type { PivotEntity } from "@/api/client";

interface Props {
  centerValue: string;
  centerType: string;
  pivots: PivotEntity[];
  onScan: (ioc: string) => void;
}

/**
 * Grafo de entidades relacionadas (node-link) en SVG puro — sin librerías, para
 * no engordar el bundle. El IOC escaneado va en el centro y cada pivote cuelga
 * radialmente, coloreado por relación. Cada nodo es clicable → escaneo encadenado.
 *
 * La paleta de relaciones es categórica y está validada para CVD sobre la
 * superficie oscura SOC (skill dataviz): teal-600 / amber-600 / violet / rose.
 * La identidad nunca es solo color: cada relación lleva su etiqueta en la leyenda
 * y el valor va escrito junto a cada nodo.
 */
const RELATION_COLORS = ["#0d9488", "#d97706", "#8b5cf6", "#f43f5e"];

function truncate(s: string, n = 22): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

export default function PivotGraph({ centerValue, centerType, pivots, onScan }: Props) {
  const W = 640;
  const H = 400;
  const cx = W / 2;
  const cy = H / 2;
  const R = 148;

  // Orden de relación estable → color fijo (nunca cíclico).
  const relations = Array.from(new Set(pivots.map((p) => p.relation)));
  const colorOf = (rel: string) =>
    RELATION_COLORS[relations.indexOf(rel) % RELATION_COLORS.length];

  const n = pivots.length;
  const nodes = pivots.map((p, i) => {
    // Empezar arriba (-90º) y repartir en círculo.
    const angle = (-Math.PI / 2) + (2 * Math.PI * i) / Math.max(n, 1);
    const x = cx + R * Math.cos(angle);
    const y = cy + R * Math.sin(angle);
    const rightHalf = Math.cos(angle) >= 0;
    return { p, x, y, rightHalf, color: colorOf(p.relation) };
  });

  return (
    <div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full h-auto"
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="Grafo de entidades relacionadas con el IOC escaneado"
      >
        {/* Aristas */}
        {nodes.map((nd, i) => (
          <line
            key={`e${i}`}
            x1={cx} y1={cy} x2={nd.x} y2={nd.y}
            stroke={nd.color} strokeOpacity={0.5} strokeWidth={2}
          />
        ))}

        {/* Nodo central (IOC escaneado) */}
        <g>
          <circle cx={cx} cy={cy} r={12} fill="#2dd4bf" stroke="#05080e" strokeWidth={2} />
          <text
            x={cx} y={cy + 28}
            textAnchor="middle"
            className="font-data"
            fontSize={12} fill="#e2e8f0" fontWeight={600}
          >
            {truncate(centerValue, 26)}
          </text>
          <text x={cx} y={cy + 43} textAnchor="middle" fontSize={9} fill="#64748b">
            {centerType.toUpperCase()}
          </text>
        </g>

        {/* Nodos pivote (clicables) */}
        {nodes.map((nd, i) => (
          <g
            key={`n${i}`}
            onClick={() => onScan(nd.p.value)}
            style={{ cursor: "pointer" }}
            className="pivot-node"
          >
            <title>{`Escanear ${nd.p.value} · ${nd.p.relation} (${nd.p.source})`}</title>
            <circle cx={nd.x} cy={nd.y} r={7} fill={nd.color} stroke="#05080e" strokeWidth={2} />
            <text
              x={nd.rightHalf ? nd.x + 11 : nd.x - 11}
              y={nd.y + 4}
              textAnchor={nd.rightHalf ? "start" : "end"}
              className="font-data"
              fontSize={11} fill="#cbd5e1"
            >
              {truncate(nd.p.value)}
            </text>
          </g>
        ))}
      </svg>

      {/* Leyenda por relación (identidad nunca solo por color) */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
        {relations.map((rel) => (
          <span key={rel} className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-500">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: colorOf(rel) }} />
            {rel}
          </span>
        ))}
      </div>

      <style>{`.pivot-node text { transition: fill .15s } .pivot-node:hover text { fill: #2dd4bf } .pivot-node:hover circle { stroke: #2dd4bf }`}</style>
    </div>
  );
}
