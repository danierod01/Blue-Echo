import { useQuery } from "@tanstack/react-query";
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, BarChart, Bar,
} from "recharts";
import { ScanSearch, ShieldAlert, Eye, BellRing } from "lucide-react";
import { getStats, type SocStats } from "@/api/client";
import { VERDICT_LABEL, cn } from "@/lib/utils";

// Colores de estado (reservados, con significado fijo) — coinciden con el veredicto.
const VERDICT_COLOR: Record<string, string> = {
  critical: "#ef4444", malicious: "#f97316",
  suspicious: "#eab308", clean: "#22c55e", pcap: "#a855f7",
};
const VERDICT_ORDER = ["critical", "malicious", "suspicious", "clean", "pcap"];
const ACCENT = "#2dd4bf";            // tono único para magnitudes
const AXIS = "#64748b";              // slate-500 (texto recesivo)
const GRID = "rgba(148,163,184,0.12)";

const TOOLTIP_STYLE = {
  background: "#0a0f18",
  border: "1px solid rgba(45,212,191,0.2)",
  borderRadius: "8px",
  fontSize: "12px",
  color: "#e2e8f0",
} as const;

function StatTile({ icon, label, value, tone }: {
  icon: React.ReactNode; label: string; value: number | string; tone?: string;
}) {
  return (
    <div className="stat-tile flex items-center gap-3">
      <div className={cn("shrink-0", tone ?? "text-accent")}>{icon}</div>
      <div className="min-w-0">
        <div className="font-data text-2xl font-bold tabular-nums leading-none text-white">{value}</div>
        <div className="soc-label mt-1 truncate">{label}</div>
      </div>
    </div>
  );
}

export default function Analytics() {
  const { data, isLoading } = useQuery<SocStats>({
    queryKey: ["stats"], queryFn: getStats, staleTime: 15_000,
  });

  const verdictData = VERDICT_ORDER
    .filter((v) => (data?.verdict_counts?.[v] ?? 0) > 0)
    .map((v) => ({ name: VERDICT_LABEL[v] ?? v, value: data!.verdict_counts[v], color: VERDICT_COLOR[v] }));

  const timelineData = (data?.timeline ?? []).map((t) => ({
    label: t.date.slice(8, 10) + "/" + t.date.slice(5, 7),   // dd/mm
    count: t.count,
  }));

  const typeData = Object.entries(data?.type_counts ?? {})
    .map(([type, count]) => ({ type: type.toUpperCase(), count }))
    .sort((a, b) => b.count - a.count);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
          Analítica SOC
        </h1>
        <p className="mt-1 text-sm text-slate-500">Métricas agregadas de tu actividad de escaneo.</p>
      </div>

      {isLoading || !data ? (
        <div className="soc-panel p-10 text-center text-sm text-slate-500">Cargando métricas…</div>
      ) : data.total_scans === 0 ? (
        <div className="soc-panel p-10 text-center text-sm text-slate-500">
          Aún no hay escaneos. Cuando empieces a analizar IOCs, aquí verás las métricas.
        </div>
      ) : (
        <>
          {/* Stat tiles */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatTile icon={<ScanSearch size={20} />} label="Escaneos totales" value={data.total_scans} />
            <StatTile icon={<ShieldAlert size={20} />} label="Críticos" value={data.verdict_counts.critical ?? 0} tone="text-red-400" />
            <StatTile icon={<Eye size={20} />} label="En watchlist" value={data.watchlist.watched} />
            <StatTile icon={<BellRing size={20} />} label="Alertas abiertas" value={data.watchlist.open_alerts} tone="text-orange-400" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Serie temporal (magnitud en el tiempo → un solo tono) */}
            <div className="soc-panel p-4">
              <span className="soc-label">Escaneos · últimos 14 días</span>
              <div className="h-56 mt-3">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="soc-area" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={ACCENT} stopOpacity={0.35} />
                        <stop offset="100%" stopColor={ACCENT} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke={GRID} vertical={false} />
                    <XAxis dataKey="label" tick={{ fill: AXIS, fontSize: 11 }} tickLine={false} axisLine={{ stroke: GRID }} interval="preserveStartEnd" />
                    <YAxis allowDecimals={false} tick={{ fill: AXIS, fontSize: 11 }} tickLine={false} axisLine={false} width={32} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: ACCENT, strokeOpacity: 0.3 }} labelFormatter={(l) => `Día ${l}`} formatter={(v) => [v as number, "escaneos"]} />
                    <Area type="monotone" dataKey="count" stroke={ACCENT} strokeWidth={2} fill="url(#soc-area)" dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Distribución por veredicto (estado → colores reservados + leyenda) */}
            <div className="soc-panel p-4">
              <span className="soc-label">Distribución por veredicto</span>
              <div className="h-56 mt-3">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={verdictData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75} paddingAngle={2} stroke="#0a0f18" strokeWidth={2}>
                      {verdictData.map((d) => <Cell key={d.name} fill={d.color} />)}
                    </Pie>
                    <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v, n) => [v as number, n as string]} />
                    <Legend wrapperStyle={{ fontSize: 11, color: AXIS }} iconType="circle" />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Tipos de IOC (magnitud por categoría → un solo tono) */}
            <div className="soc-panel p-4">
              <span className="soc-label">IOCs por tipo</span>
              <div className="h-56 mt-3">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={typeData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                    <CartesianGrid stroke={GRID} vertical={false} />
                    <XAxis dataKey="type" tick={{ fill: AXIS, fontSize: 11 }} tickLine={false} axisLine={{ stroke: GRID }} />
                    <YAxis allowDecimals={false} tick={{ fill: AXIS, fontSize: 11 }} tickLine={false} axisLine={false} width={32} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "rgba(45,212,191,0.08)" }} formatter={(v) => [v as number, "escaneos"]} />
                    <Bar dataKey="count" fill={ACCENT} radius={[4, 4, 0, 0]} maxBarSize={48} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Top amenazas (tabla, no gráfica) */}
            <div className="soc-panel p-4">
              <span className="soc-label">Top amenazas</span>
              <div className="mt-3 flex flex-col divide-y divide-white/5">
                {data.top_threats.length === 0 && (
                  <p className="text-sm text-slate-500 py-6 text-center">Sin amenazas registradas todavía.</p>
                )}
                {data.top_threats.map((t) => (
                  <div key={t.ioc_value} className="flex items-center gap-3 py-2">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: VERDICT_COLOR[t.verdict] }} />
                    <span className="font-data text-sm text-gray-200 truncate">{t.ioc_value}</span>
                    <span className="font-data text-[10px] uppercase tracking-wider text-slate-600">{t.ioc_type}</span>
                    <span className="ml-auto font-data text-sm font-bold tabular-nums" style={{ color: VERDICT_COLOR[t.verdict] }}>{t.score}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
