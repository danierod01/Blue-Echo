import { Network, ArrowUpRight, Globe, Server } from "lucide-react";
import type { PivotEntity } from "@/api/client";

interface Props {
  pivots: PivotEntity[];
  onScan: (ioc: string) => void;
}

function iconFor(type: string) {
  if (type === "domain") return <Globe size={11} className="shrink-0" />;
  return <Server size={11} className="shrink-0" />;
}

export default function Pivots({ pivots, onScan }: Props) {
  if (!pivots || pivots.length === 0) return null;

  // Agrupa por relación para dar contexto a cada bloque de pivotes.
  const groups = pivots.reduce<Record<string, PivotEntity[]>>((acc, p) => {
    (acc[p.relation] ??= []).push(p);
    return acc;
  }, {});

  return (
    <div className="soc-panel p-5">
      <div className="flex items-center gap-2 mb-1">
        <Network size={14} className="text-accent" />
        <span className="soc-label text-accent">
          Entidades relacionadas
        </span>
      </div>
      <p className="text-xs text-slate-500 mb-4">
        Pivota a un indicador relacionado — haz clic para escanearlo.
      </p>

      <div className="flex flex-col gap-4">
        {Object.entries(groups).map(([relation, items]) => (
          <div key={relation}>
            <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">{relation}</p>
            <div className="flex flex-wrap gap-1.5">
              {items.map((p) => (
                <button
                  key={`${relation}:${p.value}`}
                  type="button"
                  onClick={() => onScan(p.value)}
                  title={`Escanear ${p.value} (${p.source})`}
                  className="group flex items-center gap-1.5 rounded-lg border border-accent/15 bg-slate-900/60 px-2.5 py-1 font-data text-xs text-slate-300 transition hover:border-accent/60 hover:text-accent"
                >
                  {iconFor(p.ioc_type)}
                  <span className="truncate max-w-[220px]">{p.value}</span>
                  <ArrowUpRight size={11} className="shrink-0 text-slate-600 group-hover:text-accent" />
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
