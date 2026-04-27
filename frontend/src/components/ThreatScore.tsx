import { cn, VERDICT_BG, VERDICT_BORDER, VERDICT_COLOR, VERDICT_LABEL } from "@/lib/utils";

interface Props {
  score: number;
  verdict: string;
  iocValue: string;
  iocType: string;
}

export default function ThreatScore({ score, verdict, iocValue, iocType }: Props) {
  const color  = VERDICT_COLOR[verdict]  ?? "text-gray-400";
  const border = VERDICT_BORDER[verdict] ?? "border-gray-600";
  const bg     = VERDICT_BG[verdict]     ?? "bg-gray-800";
  const label  = VERDICT_LABEL[verdict]  ?? verdict.toUpperCase();

  // Arco SVG para el gauge
  const radius = 54;
  const circ   = 2 * Math.PI * radius;
  const pct    = Math.min(score, 100) / 100;
  const dash   = circ * pct;

  const arcColor: Record<string, string> = {
    critical:   "#ef4444",
    malicious:  "#f97316",
    suspicious: "#eab308",
    clean:      "#22c55e",
  };
  const stroke = arcColor[verdict] ?? "#6b7280";

  return (
    <div className={cn("rounded-2xl border p-6 flex flex-col items-center gap-4", border, bg)}>
      {/* Gauge */}
      <div className="relative w-36 h-36">
        <svg viewBox="0 0 128 128" className="w-full h-full -rotate-90">
          {/* Pista de fondo */}
          <circle
            cx="64" cy="64" r={radius}
            fill="none" stroke="#1f2937" strokeWidth="10"
          />
          {/* Arco de progreso */}
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke={stroke}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circ - dash}`}
            style={{ transition: "stroke-dasharray 0.6s ease" }}
          />
        </svg>
        {/* Número centrado */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("text-4xl font-bold tabular-nums", color)}>{score}</span>
          <span className="text-xs text-gray-500">/100</span>
        </div>
      </div>

      {/* Veredicto */}
      <span className={cn("text-lg font-bold tracking-widest", color)}>{label}</span>

      {/* IOC info */}
      <div className="text-center">
        <p className="text-sm font-mono text-gray-200 break-all">{iocValue}</p>
        <p className="text-xs text-gray-500 mt-0.5 uppercase tracking-wider">{iocType}</p>
      </div>
    </div>
  );
}
