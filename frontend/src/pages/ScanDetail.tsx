import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, useNavigate } from "react-router-dom";
import { Loader2, ArrowLeft, FileDown, Share2, ShieldBan, Radar } from "lucide-react";
import { getScanById, getPcapScanById, downloadScanPdf, downloadScanExport } from "@/api/client";
import ThreatScore from "@/components/ThreatScore";
import ResultsTable from "@/components/ResultsTable";
import AiSummary from "@/components/AiSummary";
import MitreAttack from "@/components/MitreAttack";
import GeoMap from "@/components/GeoMap";
import Pivots from "@/components/Pivots";
import RulesModal from "@/components/RulesModal";
import PcapAnalysisView from "@/components/PcapAnalysisView";
import { useToast } from "@/components/Toast";
import { formatDate } from "@/lib/utils";

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [rulesModal, setRulesModal] = useState<"block" | "detection" | null>(null);
  const numId = Number(id);

  // Primera consulta: datos básicos (ioc_type, fecha, etc.)
  const { data: base, isLoading: baseLoading, error: baseError } = useQuery({
    queryKey: ["scan", numId],
    queryFn: () => getScanById(numId),
    enabled: !!id,
  });

  const isPcap = base?.ioc_type === "pcap";

  // Segunda consulta: sólo si es PCAP
  const { data: pcapData, isLoading: pcapLoading } = useQuery({
    queryKey: ["scan-pcap", numId],
    queryFn: () => getPcapScanById(numId),
    enabled: isPcap,
  });

  const isLoading = baseLoading || (isPcap && pcapLoading);

  if (isLoading) {
    return (
      <div className="flex justify-center py-16 text-gray-500">
        <Loader2 size={24} className="animate-spin" />
      </div>
    );
  }

  if (baseError || !base) {
    return (
      <div className="py-10 text-center">
        <p className="text-sm text-red-400">
          Escaneo no encontrado o sin acceso.
        </p>
        <p className="mt-1 text-xs text-gray-500">
          No existe o pertenece a otro usuario — cada sesión solo puede ver sus propios escaneos.
        </p>
      </div>
    );
  }

  async function handleDownloadPdf() {
    if (!base) return;
    setDownloadingPdf(true);
    try {
      await downloadScanPdf(base.id, base.ioc_value);
      toast("Informe PDF descargado.", "success");
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo descargar el PDF.", "error");
    } finally {
      setDownloadingPdf(false);
    }
  }

  async function handleExport(format: "stix" | "misp") {
    if (!base) return;
    try {
      await downloadScanExport(base.id, format, base.ioc_value);
      toast(`Exportado a ${format.toUpperCase()}.`, "success");
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo exportar.", "error");
    }
  }

  const btnCls =
    "flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-900/60 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-accent/60 hover:text-accent disabled:opacity-50";

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate("/history")}
          className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-white transition"
        >
          <ArrowLeft size={16} />
          Volver al historial
        </button>
        <span className="text-gray-700 text-xs">{formatDate(base.created_at)}</span>
      </div>

      {/* Vista PCAP */}
      {isPcap && pcapData && (
        <PcapAnalysisView result={pcapData} />
      )}

      {/* Vista PCAP sin datos completos (escaneado antes del fix) */}
      {isPcap && !pcapData && !pcapLoading && (
        <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-6 text-sm text-gray-500 text-center">
          Este escaneo PCAP fue guardado antes de que se implementara el historial completo.
          Vuelve a analizar el fichero para ver todos los detalles.
        </div>
      )}

      {/* Vista IOC normal */}
      {!isPcap && (
        <>
          <div className="flex flex-wrap justify-end gap-2">
            <button type="button" onClick={() => handleExport("stix")} className={btnCls} title="Exportar a STIX 2.1">
              <Share2 size={13} /> STIX
            </button>
            <button type="button" onClick={() => handleExport("misp")} className={btnCls} title="Exportar a evento MISP">
              <Share2 size={13} /> MISP
            </button>
            <button type="button" onClick={() => setRulesModal("detection")} className={btnCls} title="Reglas de detección (Sigma/Suricata/YARA)">
              <Radar size={13} /> Detección
            </button>
            <button type="button" onClick={() => setRulesModal("block")} className={btnCls} title="Reglas de bloqueo (iptables/pf/DNS…)">
              <ShieldBan size={13} /> Bloqueo
            </button>
            <button type="button" onClick={handleDownloadPdf} disabled={downloadingPdf} className={btnCls} title="Descargar informe en PDF">
              {downloadingPdf ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />} Descargar PDF
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            <div className="lg:col-span-1">
              <ThreatScore
                score={base.score}
                verdict={base.verdict}
                iocValue={base.ioc_value}
                iocType={base.ioc_type}
              />
            </div>
            <div className="lg:col-span-2 flex flex-col gap-4">
              <ResultsTable
                connectorResults={base.connector_results}
                breakdown={base.breakdown}
                iocType={base.ioc_type}
              />
              {base.ai_summary && <AiSummary summary={base.ai_summary} />}
              <MitreAttack techniques={base.mitre_techniques ?? []} />
              {base.geolocation && (
                <GeoMap geo={base.geolocation} iocValue={base.ioc_value} />
              )}
            </div>
          </div>

          {/* Entidades relacionadas (pivoting) — al pulsar un pivote se escanea
              en el dashboard mediante el parámetro ?ioc= */}
          {base.pivots && base.pivots.length > 0 && (
            <Pivots
              pivots={base.pivots}
              centerValue={base.ioc_value}
              centerType={base.ioc_type}
              onScan={(ioc) => navigate(`/?ioc=${encodeURIComponent(ioc)}`)}
            />
          )}

          {rulesModal && (
            <RulesModal scanId={base.id} kind={rulesModal} onClose={() => setRulesModal(null)} />
          )}
        </>
      )}
    </div>
  );
}
