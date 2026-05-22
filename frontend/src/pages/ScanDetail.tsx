import { useQuery } from "@tanstack/react-query";
import { useParams, useNavigate } from "react-router-dom";
import { Loader2, ArrowLeft } from "lucide-react";
import { getScanById } from "@/api/client";
import ThreatScore from "@/components/ThreatScore";
import ResultsTable from "@/components/ResultsTable";
import AiSummary from "@/components/AiSummary";
import { formatDate } from "@/lib/utils";

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data, isLoading, error } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => getScanById(Number(id)),
    enabled: !!id,
  });

  if (isLoading) {
    return (
      <div className="flex justify-center py-16 text-gray-500">
        <Loader2 size={24} className="animate-spin" />
      </div>
    );
  }

  if (error || !data) {
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
        <span className="text-gray-700 text-xs">{formatDate(data.created_at)}</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <ThreatScore
            score={data.score}
            verdict={data.verdict}
            iocValue={data.ioc_value}
            iocType={data.ioc_type}
          />
        </div>
        <div className="lg:col-span-2 flex flex-col gap-4">
          <ResultsTable
            connectorResults={data.connector_results}
            breakdown={data.breakdown}
          />
          {data.ai_summary && <AiSummary summary={data.ai_summary} />}
        </div>
      </div>
    </div>
  );
}
