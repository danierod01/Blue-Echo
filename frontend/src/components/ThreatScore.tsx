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

const GLOW: Record<string, string> = {
  critical:   "shadow-[0_0_40px_rgba(239,68,68,0.25)]",
  malicious:  "shadow-[0_0_40px_rgba(249,115,22,0.2)]",
  suspicious: "shadow-[0_0_40px_rgba(234,179,8,0.15)]",
  clean:      "",
  pcap:       "",
};

export default function ThreatScore({ score, verdict, iocValue, iocType }: Props) {
  const animated = useCountUp(score);
  const color  = VERDICT_COLOR[verdict]  ?? "text-gray-400";
  const border = VERDICT_BORDER[verdict] ?? "border-gray-600";
  const bg     = VERDICT_BG[verdict]     ?? "bg-gray-800";
  const label  = VERDICT_LABEL[verdict]  ?? verdict.toUpperCase();
  const glow   = GLOW[verdict] ?? "";
  const stroke = ARC_COLOR[verdict] ?? "#6b7280";

  const radius = 54;
  const circ   = 2 * Math.PI * radius;
  const pct    = Math.min(animated, 100) / 100;
  const dash   = circ * pct;

  return (
    <div className={cn(
      "rounded-2xl border p-6 flex flex-col items-center gap-4 transition-shadow duration-700",
      border, bg, glow
    )}>
      {/* Gauge animado */}
      <div className="relative w-36 h-36">
        <svg viewBox="0 0 128 128" className="w-full h-full -rotate-90">
          <circle cx="64" cy="64" r={radius} fill="none" stroke="#1f2937" strokeWidth="10" />
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke={stroke}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circ - dash}`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("text-4xl font-bold tabular-nums transition-all duration-100", color)}>
            {animated}
          </span>
          <span className="text-xs text-gray-500">/100</span>
        </div>
      </div>

      {/* Veredicto con pulso en crítico */}
      <span className={cn(
        "text-lg font-bold tracking-widest",
        color,
        verdict === "critical" && "animate-pulse"
      )}>
        {label}
      </span>

      {/* IOC info */}
      <div className="text-center">
        <p className="text-sm font-mono text-gray-200 break-all">{iocValue}</p>
        <p className="text-xs text-gray-500 mt-0.5 uppercase tracking-wider">{iocType}</p>
      </div>
    </div>
  );
}
