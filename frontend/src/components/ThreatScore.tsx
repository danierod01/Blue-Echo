import { useEffect, useState } from "react";
import { cn, VERDICT_LABEL } from "@/lib/utils";

interface Props {
  score: number;
  verdict: string;
  iocValue: string;
  iocType: string;
}

function useCountUp(target: number, duration = 1400) {
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
  }, [target, duration]);
  return value;
}

const VERDICT_ACCENT: Record<string, { bg: string; text: string; glow: string; bar: string }> = {
  critical:   { bg: "#1a0505", text: "#ef4444", glow: "rgba(239,68,68,0.4)",    bar: "bg-red-500" },
  malicious:  { bg: "#150a02", text: "#f97316", glow: "rgba(249,115,22,0.3)",  bar: "bg-orange-500" },
  suspicious: { bg: "#121005", text: "#eab308", glow: "rgba(234,179,8,0.25)",  bar: "bg-yellow-500" },
  clean:      { bg: "#031208", text: "#22c55e", glow: "rgba(34,197,94,0.2)",   bar: "bg-green-500" },
  pcap:       { bg: "#0d0514", text: "#a855f7", glow: "rgba(168,85,247,0.25)", bar: "bg-purple-500" },
};

export default function ThreatScore({ score, verdict, iocValue, iocType }: Props) {
  const animated = useCountUp(score);
  const accent = VERDICT_ACCENT[verdict] ?? { bg: "#0f111a", text: "#6b7280", glow: "transparent", bar: "bg-gray-700" };
  const label = VERDICT_LABEL[verdict] ?? verdict.toUpperCase();
  const isThreat = verdict === "critical" || verdict === "malicious";

  return (
    <div
      className="rounded-2xl overflow-hidden relative"
      style={{ background: accent.bg, boxShadow: `0 0 60px ${accent.glow}, inset 0 1px 0 rgba(255,255,255,0.05)` }}
    >
      {/* Barra superior de color */}
      <div className={cn("h-1 w-full", accent.bar)} />

      {/* Contenido */}
      <div className="p-6 flex flex-col items-center gap-3">
        {/* Número gigante */}
        <div className="relative">
          {isThreat && (
            <div
              className="absolute inset-0 blur-2xl rounded-full animate-radarPing"
              style={{ background: accent.glow }}
            />
          )}
          <span
            className={cn(
              "text-8xl font-black tabular-nums leading-none relative z-10",
              isThreat && "animate-borderPulse"
            )}
            style={{ color: accent.text, textShadow: `0 0 30px ${accent.glow}` }}
          >
            {animated}
          </span>
        </div>

        {/* Barra de progreso */}
        <div className="w-full h-1.5 bg-black/30 rounded-full overflow-hidden">
          <div
            className={cn("h-full rounded-full transition-all duration-1000", accent.bar)}
            style={{ width: `${animated}%` }}
          />
        </div>

        {/* Veredicto */}
        <span
          className="text-sm font-bold tracking-[0.2em] uppercase"
          style={{ color: accent.text }}
        >
          {label}
        </span>

        {/* IOC */}
        <div className="w-full pt-3 border-t border-white/5 text-center">
          <p className="text-xs font-mono text-gray-300 break-all leading-relaxed">{iocValue}</p>
          <p className="text-[10px] text-gray-600 mt-1 uppercase tracking-widest">{iocType}</p>
        </div>
      </div>
    </div>
  );
}
