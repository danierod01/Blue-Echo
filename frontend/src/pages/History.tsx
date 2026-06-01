import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Loader2, Search, ChevronLeft, ChevronRight } from "lucide-react";
import { getHistory } from "@/api/client";
import { cn, VERDICT_COLOR, VERDICT_LABEL, formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

const IOC_TYPE_FILTERS: { label: string; value: string | null }[] = [
  { label: "Todos",   value: null },
  { label: "IPv4",    value: "ipv4" },
  { label: "IPv6",    value: "ipv6" },
  { label: "Hash",    value: "md5,sha1,sha256" },
  { label: "Dominio", value: "domain" },
  { label: "URL",     value: "url" },
  { label: "PCAP",    value: "pcap" },
];

const VERDICT_FILTERS: { label: string; value: string | null }[] = [
  { label: "Todos",       value: null },
  { label: "Limpio",      value: "clean" },
  { label: "Sospechoso",  value: "suspicious" },
  { label: "Malicioso",   value: "malicious" },
  { label: "Crítico",     value: "critical" },
];

const VERDICT_CHIP: Record<string, string> = {
  clean:      "border-green-800  bg-green-950/40  text-green-400",
  suspicious: "border-yellow-800 bg-yellow-950/40 text-yellow-400",
  malicious:  "border-orange-800 bg-orange-950/40 text-orange-400",
  critical:   "border-red-800    bg-red-950/40    text-red-400",
};

export default function History() {
  const navigate = useNavigate();

  const [page,       setPage]       = useState(1);
  const [iocFilter,  setIocFilter]  = useState<string | null>(null);
  const [verdict,    setVerdict]    = useState<string | null>(null);
  const [search,     setSearch]     = useState("");
  const [searchInput, setSearchInput] = useState("");

  function resetPage() { setPage(1); }

  const { data, isLoading, error } = useQuery({
    queryKey: ["history-page", page, iocFilter, verdict, search],
    queryFn: () =>
      getHistory({
        limit:    PAGE_SIZE,
        offset:   (page - 1) * PAGE_SIZE,
        ioc_type: iocFilter ?? undefined,
        verdict:  verdict   ?? undefined,
        search:   search    || undefined,
      }),
    placeholderData: (prev) => prev,
  });

  const items     = data?.items ?? [];
  const total     = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const from      = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const to        = Math.min(page * PAGE_SIZE, total);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setSearch(searchInput.trim());
    resetPage();
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Cabecera */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-bold text-white">Historial de escaneos</h1>

        {/* Buscador */}
        <form onSubmit={handleSearch} className="flex items-center gap-2">
          <div className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5">
            <Search size={14} className="text-gray-500" />
            <input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Buscar IOC…"
              className="bg-transparent text-sm text-gray-100 placeholder-gray-600 outline-none w-44"
            />
          </div>
          <button
            type="submit"
            className="rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 transition"
          >
            Buscar
          </button>
          {(search || searchInput) && (
            <button
              type="button"
              onClick={() => { setSearch(""); setSearchInput(""); resetPage(); }}
              className="text-xs text-gray-500 hover:text-gray-300 transition"
            >
              Limpiar
            </button>
          )}
        </form>
      </div>

      {/* Filtros */}
      <div className="flex flex-wrap gap-4">
        {/* Tipo de IOC */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-gray-600">Tipo:</span>
          {IOC_TYPE_FILTERS.map((f) => (
            <button
              key={f.label}
              onClick={() => { setIocFilter(f.value); resetPage(); }}
              className={cn(
                "rounded-full border px-3 py-0.5 text-xs transition",
                iocFilter === f.value
                  ? "border-blue-500 bg-blue-600/20 text-blue-300"
                  : "border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300"
              )}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Veredicto */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-gray-600">Veredicto:</span>
          {VERDICT_FILTERS.map((f) => (
            <button
              key={f.label}
              onClick={() => { setVerdict(f.value); resetPage(); }}
              className={cn(
                "rounded-full border px-3 py-0.5 text-xs transition",
                verdict === f.value
                  ? f.value
                    ? cn("border font-medium", VERDICT_CHIP[f.value])
                    : "border-blue-500 bg-blue-600/20 text-blue-300"
                  : "border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300"
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Estado: cargando / error / vacío */}
      {isLoading && (
        <div className="flex justify-center py-16 text-gray-500">
          <Loader2 size={24} className="animate-spin" />
        </div>
      )}
      {error && !isLoading && (
        <p className="text-center text-sm text-red-400 py-8">
          Error cargando el historial.
        </p>
      )}
      {!isLoading && !error && items.length === 0 && (
        <p className="text-center text-sm text-gray-600 py-8">
          No hay resultados para los filtros aplicados.
        </p>
      )}

      {/* Tabla */}
      {items.length > 0 && (
        <>
          <div className="rounded-xl border border-gray-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-900 text-gray-400 text-xs uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3 text-left">IOC</th>
                  <th className="px-4 py-3 text-left">Tipo</th>
                  <th className="px-4 py-3 text-left">Score</th>
                  <th className="px-4 py-3 text-left">Veredicto</th>
                  <th className="px-4 py-3 text-left">Fecha</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {items.map((item) => (
                  <tr
                    key={item.id}
                    className="hover:bg-gray-900/50 transition cursor-pointer"
                    onClick={() => navigate(`/history/${item.id}`)}
                  >
                    <td className="px-4 py-3 font-mono text-gray-200 max-w-xs truncate">
                      {item.ioc_value}
                    </td>
                    <td className="px-4 py-3 text-gray-500 uppercase text-xs">
                      {item.ioc_type}
                    </td>
                    <td className="px-4 py-3 font-bold tabular-nums">
                      <span className={cn(VERDICT_COLOR[item.verdict])}>{item.score}</span>
                    </td>
                    <td className={cn("px-4 py-3 font-semibold text-xs", VERDICT_COLOR[item.verdict])}>
                      {VERDICT_LABEL[item.verdict] ?? item.verdict}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                      {formatDate(item.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Paginación */}
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>
              {from}–{to} de {total} resultado{total !== 1 ? "s" : ""}
            </span>

            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(1)}
                disabled={page === 1}
                className="rounded px-2 py-1 hover:bg-gray-800 disabled:opacity-30 disabled:cursor-not-allowed transition"
              >
                «
              </button>
              <button
                onClick={() => setPage((p) => p - 1)}
                disabled={page === 1}
                className="rounded px-2 py-1 hover:bg-gray-800 disabled:opacity-30 disabled:cursor-not-allowed transition flex items-center gap-1"
              >
                <ChevronLeft size={14} /> Anterior
              </button>

              {/* Números de página */}
              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .filter((p) => p === 1 || p === totalPages || Math.abs(p - page) <= 1)
                .reduce<(number | "…")[]>((acc, p, idx, arr) => {
                  if (idx > 0 && p - (arr[idx - 1] as number) > 1) acc.push("…");
                  acc.push(p);
                  return acc;
                }, [])
                .map((p, i) =>
                  p === "…" ? (
                    <span key={`ellipsis-${i}`} className="px-1">…</span>
                  ) : (
                    <button
                      key={p}
                      onClick={() => setPage(p as number)}
                      className={cn(
                        "rounded px-2.5 py-1 transition",
                        page === p
                          ? "bg-blue-600 text-white"
                          : "hover:bg-gray-800"
                      )}
                    >
                      {p}
                    </button>
                  )
                )}

              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page === totalPages}
                className="rounded px-2 py-1 hover:bg-gray-800 disabled:opacity-30 disabled:cursor-not-allowed transition flex items-center gap-1"
              >
                Siguiente <ChevronRight size={14} />
              </button>
              <button
                onClick={() => setPage(totalPages)}
                disabled={page === totalPages}
                className="rounded px-2 py-1 hover:bg-gray-800 disabled:opacity-30 disabled:cursor-not-allowed transition"
              >
                »
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
