import { useState, useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, History, FileDown, Loader2, PanelRightClose, PanelRightOpen, Share2 } from "lucide-react";
import SkeletonResults from "@/components/SkeletonResults";
import EmptyState from "@/components/EmptyState";
import SearchBar from "@/components/SearchBar";
import BulkScanPanel from "@/components/BulkScanPanel";
import ThreatScore from "@/components/ThreatScore";
import ResultsTable from "@/components/ResultsTable";
import AiSummary from "@/components/AiSummary";
import TriagePanel from "@/components/TriagePanel";
import MitreAttack from "@/components/MitreAttack";
import Pivots from "@/components/Pivots";
import GeoMap from "@/components/GeoMap";
import HistoryList from "@/components/HistoryList";
import SourcesStatus from "@/components/SourcesStatus";
import { useToast } from "@/components/Toast";
import PcapAnalysisView from "@/components/PcapAnalysisView";
import { cn } from "@/lib/utils";
import { scanIoc, scanFile, scanPcap, getHistory, getScanById, getPcapScanById, downloadScanPdf, downloadScanExport, type ScanResponse, type PcapScanResponse, type HistoryItem } from "@/api/client";

type ScanMode = "single" | "bulk";

export default function Dashboard() {
  const [mode, setMode]             = useState<ScanMode>("single");
  const [result, setResult]         = useState<ScanResponse | null>(null);
  const [pcapResult, setPcapResult] = useState<PcapScanResponse | null>(null);
  const [errorMsg, setError]        = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try { return localStorage.getItem("be_sidebar") !== "0"; } catch { return true; }
  });
  const queryClient                 = useQueryClient();
  const { toast }                   = useToast();

  useEffect(() => {
    try { localStorage.setItem("be_sidebar", sidebarOpen ? "1" : "0"); } catch { /* ignore */ }
  }, [sidebarOpen]);

  async function handleDownloadPdf() {
    if (!result) return;
    setDownloadingPdf(true);
    try {
      await downloadScanPdf(result.id, result.ioc_value);
      toast("Informe PDF descargado.", "success");
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo descargar el PDF.", "error");
    } finally {
      setDownloadingPdf(false);
    }
  }

  async function handleExport(format: "stix" | "misp") {
    if (!result) return;
    try {
      await downloadScanExport(result.id, format, result.ioc_value);
      toast(`Exportado a ${format.toUpperCase()}.`, "success");
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo exportar.", "error");
    }
  }

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
        <div className="flex items-start justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
              Threat Intelligence
            </h1>
            <p className="mt-1 text-sm text-gray-500">
              Introduce una IP, hash, dominio o URL — o sube un fichero.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {/* Botón para reabrir el historial: solo visible cuando está oculto */}
            {history.length > 0 && !sidebarOpen && (
              <button
                onClick={() => setSidebarOpen(true)}
                className="hidden lg:flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/50 px-3 py-1 text-xs text-slate-400 transition hover:border-accent/50 hover:text-white"
                title="Mostrar historial"
              >
                <PanelRightOpen size={14} />
                Historial
              </button>
            )}
            <div className="flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 font-data text-[11px] text-accent-soft">
              <span className="w-1.5 h-1.5 rounded-full bg-accent shadow-[0_0_6px_var(--soc-accent)] animate-pulse" />
              ONLINE
            </div>
          </div>
        </div>

        {/* Toggle Individual / Masivo */}
        <div className="flex rounded-lg border border-slate-800 bg-slate-900/50 p-1 w-fit">
          {(["single", "bulk"] as ScanMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={cn(
                "px-4 py-1.5 rounded-md text-sm font-medium transition",
                mode === m
                  ? "bg-accent text-black"
                  : "text-slate-500 hover:text-slate-300"
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
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-3 rounded-lg border border-accent/20 bg-accent/5 px-4 py-3">
              <div className="w-2 h-2 rounded-full bg-accent shadow-[0_0_8px_var(--soc-accent)] animate-pulse" />
              <span className="text-sm text-accent-soft font-data">
                {pcapMutation.isPending ? "Analizando tráfico PCAP con IA" : "Consultando fuentes de Threat Intelligence"}
                <span className="inline-flex gap-0.5 ml-1">
                  {[0,1,2].map(i => (
                    <span key={i} className="animate-terminalDot" style={{ animationDelay: `${i * 0.2}s` }}>.</span>
                  ))}
                </span>
              </span>
            </div>
            {!pcapMutation.isPending && <SkeletonResults />}
          </div>
        )}

        {/* Resultados */}
        {mode === "single" && result && !loading && (
          <div className="flex flex-col gap-6">
            <div className="flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => handleExport("stix")}
                className="flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-900/60 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-accent/60 hover:text-accent"
                title="Exportar a STIX 2.1 (bundle para SIEM/TIP)"
              >
                <Share2 size={13} />
                STIX
              </button>
              <button
                type="button"
                onClick={() => handleExport("misp")}
                className="flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-900/60 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-accent/60 hover:text-accent"
                title="Exportar a evento MISP (JSON)"
              >
                <Share2 size={13} />
                MISP
              </button>
              <button
                type="button"
                onClick={handleDownloadPdf}
                disabled={downloadingPdf}
                className="flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-900/60 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-accent/60 hover:text-accent disabled:opacity-50"
                title="Descargar informe en PDF"
              >
                {downloadingPdf ? (
                  <Loader2 size={13} className="animate-spin" />
                ) : (
                  <FileDown size={13} />
                )}
                Descargar PDF
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-start">
              <div className="animate-[fadeSlideIn_0.4s_ease_forwards]">
                <ThreatScore
                  score={result.score}
                  verdict={result.verdict}
                  iocValue={result.ioc_value}
                  iocType={result.ioc_type}
                />
              </div>
              <div className="md:col-span-2 soc-panel p-4 animate-[fadeSlideIn_0.4s_ease_0.1s_forwards] opacity-0">
                <div className="flex items-center justify-between mb-3">
                  <span className="soc-label">Resultados por fuente</span>
                  <span className="font-data text-[10px] text-slate-600">
                    {Object.keys(result.connector_results).filter(k => k !== "__pcap_data__").length} conectores
                  </span>
                </div>
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

            <div className="animate-[fadeSlideIn_0.4s_ease_0.25s_forwards] opacity-0">
              <TriagePanel
                scanId={result.id}
                triage={result.triage}
                note={result.note}
                tags={result.tags}
                onUpdated={() => queryClient.invalidateQueries({ queryKey: ["history"] })}
              />
            </div>

            <div className="animate-[fadeSlideIn_0.4s_ease_0.3s_forwards] opacity-0">
              <MitreAttack techniques={result.mitre_techniques} />
            </div>

            {result.pivots && result.pivots.length > 0 && (
              <div className="animate-[fadeSlideIn_0.4s_ease_0.35s_forwards] opacity-0">
                <Pivots pivots={result.pivots} onScan={(ioc) => mutation.mutate({ ioc })} />
              </div>
            )}

            <div className="animate-[fadeSlideIn_0.4s_ease_0.4s_forwards] opacity-0">
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
          <EmptyState />
        )}
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Sidebar — historial reciente                                      */}
      {/* ---------------------------------------------------------------- */}
      {history.length > 0 && sidebarOpen && (
        <aside className="w-72 shrink-0 hidden lg:flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 soc-label">
              <History size={13} />
              Recientes
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="flex items-center gap-1 text-[11px] text-slate-500 transition hover:text-accent"
              title="Ocultar historial"
            >
              <PanelRightClose size={13} />
              Ocultar
            </button>
          </div>
          <div className="soc-panel p-2">
            <HistoryList items={history} onSelect={handleHistorySelect} />
          </div>
        </aside>
      )}
    </div>
  );
}
