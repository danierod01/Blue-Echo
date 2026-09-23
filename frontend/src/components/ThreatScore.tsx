import { useEffect, useState } from "react";
import { cn, VERDICT_LABEL } from "@/lib/utils";

interface Props {
  score: number;
  verdict: string;
  iocValue: string;
  iocType: string;
}

function useCountUp(target: number, duration = 1200) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    setValue(0);
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min((now - start) / duration, 1);
      setValue(Math.round((1 - Math.pow(1 - p, 4)) * target));
      if (p < 1) requestAnimationFrame(tick);
    };
    const id = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(id);
  }, [target]);
  return value;
}

const COLORS: Record<string, { num: string; label: string; bar: string; glow: string; dim: string }> = {
  critical:   { num: "#f87171", label: "#ef4444", bar: "#ef4444", glow: "rgba(239,68,68,0.35)",   dim: "rgba(239,68,68,0.06)" },
  malicious:  { num: "#fb923c", label: "#f97316", bar: "#f97316", glow: "rgba(249,115,22,0.3)",   dim: "rgba(249,115,22,0.05)" },
  suspicious: { num: "#fbbf24", label: "#eab308", bar: "#eab308", glow: "rgba(234,179,8,0.25)",   dim: "rgba(234,179,8,0.05)" },
  clean:      { num: "#4ade80", label: "#22c55e", bar: "#22c55e", glow: "rgba(34,197,94,0.2)",    dim: "rgba(34,197,94,0.04)" },
  pcap:       { num: "#c084fc", label: "#a855f7", bar: "#a855f7", glow: "rgba(168,85,247,0.25)",  dim: "rgba(168,85,247,0.05)" },
};
const DEFAULT_C = { num: "#9ca3af", label: "#6b7280", bar: "#4b5563", glow: "transparent", dim: "transparent" };

export default function ThreatScore({ score, verdict, iocValue, iocType }: Props) {
  const animated = useCountUp(score);
  const c = COLORS[verdict] ?? DEFAULT_C;
  const label = VERDICT_LABEL[verdict] ?? verdict.toUpperCase();
  const isThreat = verdict === "critical" || verdict === "malicious";

  return (
    <div
      className="relative overflow-hidden rounded-xl h-full min-h-[280px] flex flex-col justify-between p-6"
      style={{ background: `linear-gradient(135deg, ${c.dim} 0%, #08080f 60%)`, boxShadow: `0 0 60px ${c.glow}` }}
    >
      {/* Línea de acento superior */}
      <div className="absolute top-0 left-0 right-0 h-[2px]" style={{ background: `linear-gradient(to right, transparent, ${c.bar}, transparent)` }} />

      {/* Etiqueta tipo */}
      <div>
        <span className="text-[10px] uppercase tracking-[0.2em] font-medium" style={{ color: c.label }}>
          {label}
        </span>
      </div>

      {/* Número */}
      <div className="flex items-end gap-2 my-4">
        <span
          className={cn("font-black tabular-nums leading-none", isThreat && "animate-borderPulse")}
          style={{ fontSize: "clamp(4rem,10vw,6rem)", color: c.num, textShadow: `0 0 40px ${c.glow}` }}
        >
          {animated}
        </span>
        <span className="text-gray-600 font-data text-lg mb-2">/100</span>
      </div>

      {/* Barra */}
      <div className="space-y-4">
        <div className="h-1 bg-white/5 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-1000"
            style={{ width: `${animated}%`, background: c.bar, boxShadow: `0 0 8px ${c.glow}` }}
          />
        </div>

        {/* IOC */}
        <div className="border-t border-white/5 pt-3">
          <p className="font-data text-xs text-gray-300 break-all leading-relaxed">{iocValue}</p>
          <p className="text-[10px] uppercase tracking-[0.15em] text-gray-600 mt-1">{iocType}</p>
        </div>
      </div>
    </div>
  );
}
