import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, Plus, RefreshCw, Trash2, BellRing, Check, Loader2, ArrowRight } from "lucide-react";
import {
  addWatched, listWatched, removeWatched, checkWatched,
  listWatchAlerts, ackWatchAlert,
  type WatchAlert,
} from "@/api/client";
import { VERDICT_LABEL, cn } from "@/lib/utils";
import { useToast } from "@/components/Toast";

const VERDICT_DOT: Record<string, string> = {
  critical: "bg-red-500", malicious: "bg-orange-500",
  suspicious: "bg-yellow-400", clean: "bg-emerald-500", pcap: "bg-purple-500",
};

function verdictLabel(v: string | null): string {
  return v ? (VERDICT_LABEL[v] ?? v.toUpperCase()) : "—";
}

function fmt(iso: string | null): string {
  if (!iso) return "nunca";
  return new Date(iso).toLocaleString("es-ES", {
    day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

export default function Watchlist() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [value, setValue] = useState("");
  const [checking, setChecking] = useState<number | null>(null);

  const watched = useQuery({ queryKey: ["watchlist"], queryFn: listWatched, staleTime: 10_000 });
  const alerts = useQuery({ queryKey: ["watch-alerts"], queryFn: listWatchAlerts, staleTime: 10_000 });

  const addMut = useMutation({
    mutationFn: (ioc: string) => addWatched(ioc),
    onSuccess: () => { setValue(""); qc.invalidateQueries({ queryKey: ["watchlist"] }); toast("IOC añadido a la watchlist.", "success"); },
    onError: (e: Error) => toast(e.message, "error"),
  });
  const removeMut = useMutation({
    mutationFn: (id: number) => removeWatched(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["watchlist"] }),
  });
  const ackMut = useMutation({
    mutationFn: (id: number) => ackWatchAlert(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["watch-alerts"] }),
  });

  async function handleCheck(id: number) {
    setChecking(id);
    try {
      const res = await checkWatched(id);
      qc.invalidateQueries({ queryKey: ["watchlist"] });
      if (res.alert) {
        qc.invalidateQueries({ queryKey: ["watch-alerts"] });
        toast(`¡Cambio de veredicto! ${res.alert.old_verdict} → ${res.alert.new_verdict}`, "error");
      } else {
        toast(`Comprobado: ${verdictLabel(res.last_verdict)}.`, "success");
      }
    } catch (e) {
      toast(e instanceof Error ? e.message : "Error al comprobar.", "error");
    } finally {
      setChecking(null);
    }
  }

  const openAlerts = (alerts.data ?? []).filter((a) => !a.acknowledged);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
          Watchlist
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          IOCs bajo monitorización continua — se re-escanean solos y te avisan si cambia el veredicto.
        </p>
      </div>

      {/* Añadir */}
      <form
        onSubmit={(e) => { e.preventDefault(); if (value.trim()) addMut.mutate(value.trim()); }}
        className="flex items-center gap-2 rounded-xl border border-accent/15 bg-[var(--soc-bg-elev)] px-4 py-3"
      >
        <Eye size={18} className="shrink-0 text-accent/60" />
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Añade una IP, hash, dominio o URL a vigilar"
          className="flex-1 bg-transparent text-sm text-gray-100 placeholder-gray-600 outline-none font-data"
        />
        <button
          type="submit"
          disabled={addMut.isPending || !value.trim()}
          className="shrink-0 flex items-center gap-1.5 rounded-lg bg-accent px-4 py-1.5 text-sm font-semibold text-black hover:bg-accent-soft disabled:opacity-40 transition"
        >
          <Plus size={15} /> Vigilar
        </button>
      </form>

      {/* Alertas de cambio de veredicto */}
      {openAlerts.length > 0 && (
        <div className="soc-panel p-4 border-red-500/30">
          <div className="flex items-center gap-2 mb-3">
            <BellRing size={14} className="text-red-400" />
            <span className="soc-label text-red-400">Alertas de cambio de veredicto ({openAlerts.length})</span>
          </div>
          <div className="flex flex-col gap-2">
            {openAlerts.map((a: WatchAlert) => (
              <div key={a.id} className="flex items-center gap-3 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2">
                <span className="font-data text-xs text-gray-200 truncate">{a.ioc_value}</span>
                <span className="flex items-center gap-1.5 font-data text-[11px] text-slate-400">
                  <span className={cn("w-1.5 h-1.5 rounded-full", VERDICT_DOT[a.old_verdict ?? ""] ?? "bg-slate-600")} />
                  {verdictLabel(a.old_verdict)}
                  <ArrowRight size={11} className="text-slate-600" />
                  <span className={cn("w-1.5 h-1.5 rounded-full", VERDICT_DOT[a.new_verdict] ?? "bg-slate-600")} />
                  {verdictLabel(a.new_verdict)}
                </span>
                <span className="ml-auto text-[11px] text-slate-600">{fmt(a.created_at)}</span>
                <button
                  onClick={() => ackMut.mutate(a.id)}
                  className="shrink-0 flex items-center gap-1 text-[11px] text-slate-400 hover:text-accent transition"
                  title="Reconocer alerta"
                >
                  <Check size={13} /> Reconocer
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabla de IOCs vigilados */}
      <div className="soc-panel p-4">
        <div className="flex items-center justify-between mb-3">
          <span className="soc-label">IOCs vigilados</span>
          <span className="font-data text-xs text-slate-500">{watched.data?.length ?? 0} en seguimiento</span>
        </div>

        {watched.data && watched.data.length === 0 && (
          <p className="text-sm text-slate-500 py-6 text-center">
            No hay IOCs en la watchlist. Añade uno arriba para empezar a vigilarlo.
          </p>
        )}

        <div className="flex flex-col divide-y divide-white/5">
          {(watched.data ?? []).map((w) => (
            <div key={w.id} className="grid grid-cols-[1fr_auto_auto_auto] items-center gap-3 py-2.5">
              <div className="min-w-0">
                <div className="font-data text-sm text-gray-200 truncate">{w.ioc_value}</div>
                <div className="font-data text-[10px] uppercase tracking-wider text-slate-600">{w.ioc_type}</div>
              </div>
              <div className="flex items-center gap-1.5 font-data text-xs text-slate-300">
                <span className={cn("w-1.5 h-1.5 rounded-full", VERDICT_DOT[w.last_verdict ?? ""] ?? "bg-slate-700")} />
                {verdictLabel(w.last_verdict)}
              </div>
              <div className="text-[11px] text-slate-500 font-data hidden sm:block">rev. {fmt(w.last_checked_at)}</div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => handleCheck(w.id)}
                  disabled={checking === w.id}
                  className="p-1.5 rounded-md text-slate-500 hover:text-accent hover:bg-white/5 transition"
                  title="Comprobar ahora"
                >
                  {checking === w.id ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                </button>
                <button
                  onClick={() => removeMut.mutate(w.id)}
                  className="p-1.5 rounded-md text-slate-500 hover:text-red-400 hover:bg-white/5 transition"
                  title="Dejar de vigilar"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
