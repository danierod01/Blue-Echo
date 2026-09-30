import { useState } from "react";
import { Network, ArrowUpRight, Globe, Server, Share2, List } from "lucide-react";
import type { PivotEntity } from "@/api/client";
import PivotGraph from "@/components/PivotGraph";
import { cn } from "@/lib/utils";

interface Props {
  pivots: PivotEntity[];
  onScan: (ioc: string) => void;
  centerValue?: string;
  centerType?: string;
}

function iconFor(type: string) {
  if (type === "domain") return <Globe size={11} className="shrink-0" />;
  return <Server size={11} className="shrink-0" />;
}

export default function Pivots({ pivots, onScan, centerValue, centerType }: Props) {
  const [view, setView] = useState<"graph" | "list">("graph");
  if (!pivots || pivots.length === 0) return null;

  // Agrupa por relación para dar contexto a cada bloque de pivotes.
  const groups = pivots.reduce<Record<string, PivotEntity[]>>((acc, p) => {
    (acc[p.relation] ??= []).push(p);
    return acc;
  }, {});

  const canGraph = Boolean(centerValue && centerType);

  return (
    <div className="soc-panel p-5">
      <div className="flex items-center justify-between gap-2 mb-1">
        <div className="flex items-center gap-2">
          <Network size={14} className="text-accent" />
          <span className="soc-label text-accent">Entidades relacionadas</span>
        </div>
        {canGraph && (
          <div className="flex items-center gap-1 rounded-lg border border-slate-800 p-0.5">
            <button
              onClick={() => setView("graph")}
              className={cn("flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium transition",
                view === "graph" ? "bg-accent/10 text-accent" : "text-slate-500 hover:text-slate-300")}
            >
              <Share2 size={11} /> Grafo
            </button>
            <button
              onClick={() => setView("list")}
              className={cn("flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium transition",
                view === "list" ? "bg-accent/10 text-accent" : "text-slate-500 hover:text-slate-300")}
            >
              <List size={11} /> Lista
            </button>
          </div>
        )}
      </div>
      <p className="text-xs text-slate-500 mb-4">
        Pivota a un indicador relacionado — haz clic para escanearlo.
      </p>

      {canGraph && view === "graph" && (
        <PivotGraph
          centerValue={centerValue!}
          centerType={centerType!}
          pivots={pivots}
          onScan={onScan}
        />
      )}

      {(!canGraph || view === "list") && (
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
      )}
    </div>
  );
}
