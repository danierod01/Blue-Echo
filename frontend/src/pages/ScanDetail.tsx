import { useQuery } from "@tanstack/react-query";
import { useParams, useNavigate } from "react-router-dom";
import { Loader2, ArrowLeft } from "lucide-react";
import { getScanById, getPcapScanById } from "@/api/client";
import ThreatScore from "@/components/ThreatScore";
import ResultsTable from "@/components/ResultsTable";
import AiSummary from "@/components/AiSummary";
import MitreAttack from "@/components/MitreAttack";
import GeoMap from "@/components/GeoMap";
import PcapAnalysisView from "@/components/PcapAnalysisView";
import { formatDate } from "@/lib/utils";

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
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
      <p className="text-center text-sm text-red-400 py-8">
        No se pudo cargar el escaneo.
      </p>
    );
  }

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
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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
            />
            {base.ai_summary && <AiSummary summary={base.ai_summary} />}
            <MitreAttack techniques={base.mitre_techniques ?? []} />
            {base.geolocation && (
              <GeoMap geo={base.geolocation} iocValue={base.ioc_value} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
