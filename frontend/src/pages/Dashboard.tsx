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
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Intelligence Correlator</h1>
          <p className="mt-1 text-sm text-gray-400">
            Introduce una IP, hash, dominio o URL — o sube un fichero de logs.
          </p>
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

        {/* Cargando */}
        {loading && <SkeletonResults />}

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
        {!result && !loading && !errorMsg && (
          <div className="flex flex-col items-center justify-center gap-2 py-16 text-gray-700">
            <p className="text-sm">Los resultados aparecerán aquí tras el escaneo.</p>
          </div>
        )}
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
