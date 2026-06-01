import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Loader2, History } from "lucide-react";
import SearchBar from "@/components/SearchBar";
import BulkScanPanel from "@/components/BulkScanPanel";
import ThreatScore from "@/components/ThreatScore";
import ResultsTable from "@/components/ResultsTable";
import AiSummary from "@/components/AiSummary";
import MitreAttack from "@/components/MitreAttack";
import GeoMap from "@/components/GeoMap";
import HistoryList from "@/components/HistoryList";
import SourcesStatus from "@/components/SourcesStatus";
import PcapAnalysisView from "@/components/PcapAnalysisView";
import { cn } from "@/lib/utils";
import { scanIoc, scanFile, scanPcap, getHistory, getScanById, getPcapScanById, type ScanResponse, type PcapScanResponse, type HistoryItem } from "@/api/client";

type ScanMode = "single" | "bulk";

export default function Dashboard() {
  const [mode, setMode]             = useState<ScanMode>("single");
  const [result, setResult]         = useState<ScanResponse | null>(null);
  const [pcapResult, setPcapResult] = useState<PcapScanResponse | null>(null);
  const [errorMsg, setError]        = useState<string | null>(null);
  const queryClient                 = useQueryClient();

  // Historial reciente para el sidebar
  const { data: historyPage } = useQuery({
    queryKey: ["history"],
    queryFn:  () => getHistory({ limit: 10 }),
    staleTime: 15_000,
  });
  const history = historyPage?.items ?? [];

  const mutation = useMutation({
    mutationFn: async (input: { ioc?: string; file?: File }) =>
      input.file ? scanFile(input.file) : scanIoc(input.ioc!),
    onSuccess: (data) => {
      setResult(data);
      setPcapResult(null);
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["history"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setResult(null);
      setPcapResult(null);
    },
  });

  const pcapMutation = useMutation({
    mutationFn: (file: File) => scanPcap(file),
    onSuccess: (data) => {
      setPcapResult(data);
      setResult(null);
      setError(null);
    },
    onError: (err: Error) => {
      setError(err.message);
      setPcapResult(null);
      setResult(null);
    },
  });

  async function handleHistorySelect(item: HistoryItem) {
    try {
      if (item.ioc_type === "pcap") {
        const data = await getPcapScanById(item.id);
        setPcapResult(data);
        setResult(null);
      } else {
        const data = await getScanById(item.id);
        setResult(data);
        setPcapResult(null);
      }
      setError(null);
    } catch {
      setError("No se pudo cargar el escaneo.");
    }
  }

  const loading = mutation.isPending || pcapMutation.isPending;

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

        {/* Toggle Individual / Masivo */}
        <div className="flex rounded-lg border border-gray-800 bg-gray-900/50 p-1 w-fit">
          {(["single", "bulk"] as ScanMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={cn(
                "px-4 py-1.5 rounded-md text-sm font-medium transition",
                mode === m
                  ? "bg-blue-600 text-white"
                  : "text-gray-500 hover:text-gray-300"
              )}
            >
              {m === "single" ? "Individual" : "Masivo"}
            </button>
          ))}
        </div>

        {/* Barra de búsqueda / Panel masivo */}
        {mode === "single" ? (
          <SearchBar
            loading={loading}
            onScanIoc={(ioc) => mutation.mutate({ ioc })}
            onScanFile={(file) => mutation.mutate({ file })}
            onScanPcap={(file) => pcapMutation.mutate(file)}
          />
        ) : (
          <BulkScanPanel
            onComplete={() => queryClient.invalidateQueries({ queryKey: ["history"] })}
          />
        )}

        {/* Estado de conectores */}
        <SourcesStatus />

        {/* Resultados del modo individual (ocultos en modo masivo) */}
        {/* Error */}
        {mode === "single" && errorMsg && (
          <div className="flex items-center gap-3 rounded-xl border border-red-800 bg-red-900/20 px-4 py-3 text-sm text-red-400">
            <AlertCircle size={16} className="shrink-0" />
            {errorMsg}
          </div>
        )}

        {/* Cargando */}
        {mode === "single" && loading && (
          <div className="flex flex-col items-center justify-center gap-3 py-12 text-gray-500">
            <Loader2 size={32} className="animate-spin text-blue-500" />
            <p className="text-sm">
              {pcapMutation.isPending
                ? "Analizando tráfico PCAP con IA…"
                : "Consultando fuentes de Threat Intelligence…"}
            </p>
          </div>
        )}

        {/* Resultados */}
        {mode === "single" && result && !loading && (
          <div className="flex flex-col gap-6">
            {/* Score + Tabla */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-start">
              <ThreatScore
                score={result.score}
                verdict={result.verdict}
                iocValue={result.ioc_value}
                iocType={result.ioc_type}
              />

              <div className="md:col-span-2 flex flex-col gap-4">
                <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-5">
                  <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
                    Resultados por fuente
                  </h2>
                  <ResultsTable
                    connectorResults={result.connector_results}
                    breakdown={result.breakdown}
                  />
                </div>
              </div>
            </div>

            {/* Análisis IA */}
            <AiSummary summary={result.ai_summary} />

            {/* MITRE ATT&CK */}
            <MitreAttack techniques={result.mitre_techniques} />

            {/* Geolocalización */}
            {result.geolocation ? (
              <GeoMap geo={result.geolocation} iocValue={result.ioc_value} />
            ) : (
              ["ipv4", "ipv6", "domain", "url"].includes(result.ioc_type) && (
                <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-5 text-sm text-gray-500">
                  No se ha podido determinar la geolocalización.
                </div>
              )
            )}
          </div>
        )}

        {/* Resultados PCAP */}
        {mode === "single" && pcapResult && !loading && (
          <PcapAnalysisView
            result={pcapResult}
            onScanIoc={(ioc) => mutation.mutate({ ioc })}
          />
        )}

        {/* Estado vacío */}
        {mode === "single" && !result && !pcapResult && !loading && !errorMsg && (
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
