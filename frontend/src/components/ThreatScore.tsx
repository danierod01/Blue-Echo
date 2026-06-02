import { useEffect, useState } from "react";
import { cn, VERDICT_BG, VERDICT_BORDER, VERDICT_COLOR, VERDICT_LABEL } from "@/lib/utils";

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
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(eased * target));
      if (progress < 1) requestAnimationFrame(tick);
    };
    const id = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(id);
  }, [target, duration]);
  return value;
}

const ARC_COLOR: Record<string, string> = {
  critical:   "#ef4444",
  malicious:  "#f97316",
  suspicious: "#eab308",
  clean:      "#22c55e",
  pcap:       "#a855f7",
};

const RING_GLOW: Record<string, string> = {
  critical:  "rgba(239,68,68,0.4)",
  malicious: "rgba(249,115,22,0.3)",
};

export default function ThreatScore({ score, verdict, iocValue, iocType }: Props) {
  const animated = useCountUp(score);
  const color  = VERDICT_COLOR[verdict]  ?? "text-gray-400";
  const border = VERDICT_BORDER[verdict] ?? "border-gray-600";
  const bg     = VERDICT_BG[verdict]     ?? "bg-gray-800";
  const label  = VERDICT_LABEL[verdict]  ?? verdict.toUpperCase();
  const stroke = ARC_COLOR[verdict] ?? "#6b7280";
  const glowColor = RING_GLOW[verdict];

  const radius = 54;
  const circ   = 2 * Math.PI * radius;
  const dash   = circ * Math.min(animated, 100) / 100;

  const isThreat = verdict === "critical" || verdict === "malicious";

  return (
    <div className={cn(
      "rounded-2xl border p-6 flex flex-col items-center gap-4 transition-all duration-700 relative overflow-hidden",
      border, bg,
      glowColor && `shadow-[0_0_40px_${glowColor}]`
    )}>
      {/* Fondo decorativo */}
      <div
        className="absolute inset-0 opacity-30 pointer-events-none"
        style={{
          background: `radial-gradient(ellipse at 50% 0%, ${stroke}15 0%, transparent 70%)`,
        }}
      />

      {/* Gauge */}
      <div className="relative w-36 h-36">
        {/* Anillos de pulso para crítico/malicioso */}
        {isThreat && (
          <>
            <div
              className="absolute inset-0 rounded-full animate-radarPing border"
              style={{ borderColor: `${stroke}50` }}
            />
            <div
              className="absolute inset-0 rounded-full animate-radarPing border"
              style={{ borderColor: `${stroke}30`, animationDelay: "1s" }}
            />
          </>
        )}

        <svg viewBox="0 0 128 128" className="w-full h-full -rotate-90">
          {/* Track */}
          <circle cx="64" cy="64" r={radius} fill="none" stroke="#1f2937" strokeWidth="10" />
          {/* Glow track */}
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke={stroke}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circ - dash}`}
            style={{ filter: `drop-shadow(0 0 6px ${stroke}80)` }}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("text-4xl font-bold tabular-nums", color)}>{animated}</span>
          <span className="text-xs text-gray-600">/100</span>
        </div>
      </div>

      {/* Veredicto */}
      <span className={cn(
        "text-lg font-bold tracking-widest relative z-10",
        color,
        isThreat && "animate-borderPulse"
      )}>
        {label}
      </span>

      {/* IOC */}
      <div className="text-center relative z-10">
        <p className="text-sm font-mono text-gray-200 break-all">{iocValue}</p>
        <p className="text-xs text-gray-500 mt-0.5 uppercase tracking-wider">{iocType}</p>
      </div>
    </div>
  );
}
