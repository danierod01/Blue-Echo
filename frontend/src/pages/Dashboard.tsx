import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, History } from "lucide-react";
import SearchBar from "@/components/SearchBar";
import ThreatScore from "@/components/ThreatScore";
import ResultsTable from "@/components/ResultsTable";
import AiSummary from "@/components/AiSummary";
import HistoryList from "@/components/HistoryList";
import SourcesStatus from "@/components/SourcesStatus";
import SkeletonResults from "@/components/SkeletonResults";
import EmptyState from "@/components/EmptyState";
import { scanIoc, scanFile, getHistory, getScanById, type ScanResponse } from "@/api/client";

export default function Dashboard() {
  const [result, setResult]   = useState<ScanResponse | null>(null);
  const [errorMsg, setError]  = useState<string | null>(null);
  const queryClient           = useQueryClient();

  // Historial reciente para el sidebar
  const { data: history = [] } = useQuery({
    queryKey: ["history"],
    queryFn:  () => getHistory(10),
    staleTime: 15_000,
  });

  const mutation = useMutation({
    mutationFn: async (input: { ioc?: string; file?: File }) =>
      input.file ? scanFile(input.file) : scanIoc(input.ioc!),
    onSuccess: (data) => {
      setResult(data);
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["history"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setResult(null);
    },
  });

  async function handleHistorySelect(item: { id: number }) {
    try {
      const data = await getScanById(item.id);
      setResult(data);
      setError(null);
    } catch {
      setError("No se pudo cargar el escaneo.");
    }
  }

  const loading = mutation.isPending;

  return (
    <div className="flex gap-6">
      {/* ---------------------------------------------------------------- */}
      {/* Columna principal                                                 */}
      {/* ---------------------------------------------------------------- */}
      <div className="flex-1 flex flex-col gap-6 min-w-0">
        {/* Cabecera */}
        <div className="flex items-start justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
              Threat Intelligence
            </h1>
            <p className="mt-1 text-sm text-gray-500">
              Introduce una IP, hash, dominio o URL — o sube un fichero.
            </p>
          </div>
          <div className="flex items-center gap-1.5 rounded-full border border-green-800/60 bg-green-950/30 px-3 py-1 text-xs text-green-400">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            Online
          </div>
        </div>

        {/* Barra de búsqueda */}
        <SearchBar
          loading={loading}
          onScanIoc={(ioc) => mutation.mutate({ ioc })}
          onScanFile={(file) => mutation.mutate({ file })}
        />

        {/* Estado de conectores */}
        <SourcesStatus />

        {/* Error */}
        {errorMsg && (
          <div className="flex items-center gap-3 rounded-xl border border-red-800 bg-red-900/20 px-4 py-3 text-sm text-red-400">
            <AlertCircle size={16} className="shrink-0" />
            {errorMsg}
          </div>
        )}

        {/* Escaneando */}
        {loading && (
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-3 rounded-xl border border-blue-500/20 bg-blue-500/5 px-4 py-3">
              <div className="w-2 h-2 rounded-full bg-blue-400 shadow-[0_0_8px_rgba(59,130,246,0.8)] animate-pulse" />
              <span className="text-sm text-blue-300 font-mono">
                Consultando fuentes de Threat Intelligence
                <span className="inline-flex gap-0.5 ml-1">
                  {[0,1,2].map(i => (
                    <span key={i} className="animate-terminalDot" style={{ animationDelay: `${i * 0.2}s` }}>.</span>
                  ))}
                </span>
              </span>
            </div>
            <SkeletonResults />
          </div>
        )}

        {/* Resultados */}
        {result && !loading && (
          <div className="flex flex-col gap-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-start">
              <div className="animate-[fadeSlideIn_0.4s_ease_forwards]">
                <ThreatScore
                  score={result.score}
                  verdict={result.verdict}
                  iocValue={result.ioc_value}
                  iocType={result.ioc_type}
                />
              </div>
              <div className="md:col-span-2 animate-[fadeSlideIn_0.4s_ease_0.1s_forwards] opacity-0">
                <ResultsTable
                  connectorResults={result.connector_results}
                  breakdown={result.breakdown}
                  iocType={result.ioc_type}
                />
              </div>
            </div>
            <div className="animate-[fadeSlideIn_0.4s_ease_0.2s_forwards] opacity-0">
              <AiSummary summary={result.ai_summary} />
            </div>
          </div>
        )}

        {/* Estado vacío */}
        {!result && !loading && !errorMsg && <EmptyState />}
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Sidebar — historial reciente                                      */}
      {/* ---------------------------------------------------------------- */}
      {history.length > 0 && (
        <aside className="w-72 shrink-0 hidden lg:flex flex-col gap-3">
          <div className="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wider">
            <History size={13} />
            Recientes
          </div>
          <div className="rounded-xl border border-gray-800 bg-gray-900/30 p-2">
            <HistoryList items={history} onSelect={handleHistorySelect} />
          </div>
        </aside>
      )}
    </div>
  );
}
