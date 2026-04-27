import { CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { cn, VERDICT_COLOR } from "@/lib/utils";
import type { ConnectorResult } from "@/api/client";

interface Props {
  connectorResults: Record<string, ConnectorResult>;
  breakdown: Record<string, number>;
}

const SOURCE_LABEL: Record<string, string> = {
  virustotal:    "VirusTotal",
  abuseipdb:     "AbuseIPDB",
  shodan:        "Shodan",
  otx:           "AlienVault OTX",
  malwarebazaar: "MalwareBazaar",
  urlhaus:       "URLhaus",
  greynoise:     "GreyNoise",
};

function KeyFinding({ result }: { result: ConnectorResult }): JSX.Element {
  const d = result.data;
  if (!result.success) return <span className="text-gray-600 italic text-xs">{result.error ?? "error"}</span>;

  if (result.source === "virustotal") {
    const mal = d.malicious as number ?? 0;
    const tot = d.total as number ?? 0;
    return <span>{mal}/{tot} motores</span>;
  }
  if (result.source === "abuseipdb") {
    const conf = d.confidence as number ?? 0;
    const rep  = d.total_reports as number ?? 0;
    return <span>Confianza {conf}% · {rep} reportes</span>;
  }
  if (result.source === "shodan") {
    const ports = (d.open_ports as number[] ?? []).join(", ");
    return <span>{ports || "Sin puertos abiertos"}</span>;
  }
  if (result.source === "otx") {
    const pulses = d.pulse_count as number ?? 0;
    return <span>{pulses} pulsos activos</span>;
  }
  if (result.source === "malwarebazaar") {
    return <span>{d.found ? "Hash conocido" : "No encontrado"}</span>;
  }
  if (result.source === "greynoise") {
    const cls = d.classification as string ?? "unknown";
    return <span className="capitalize">{cls}</span>;
  }
  if (result.source === "urlhaus") {
    return <span>{d.found ? "URL conocida" : "No encontrada"}</span>;
  }
  return <span className="text-gray-500">—</span>;
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const labels: Record<string, string> = {
    malicious:  "Malicioso",
    suspicious: "Sospechoso",
    clean:      "Limpio",
    unknown:    "Desconocido",
    error:      "Error",
  };
  return (
    <span className={cn("text-xs font-semibold", VERDICT_COLOR[verdict] ?? "text-gray-500")}>
      {labels[verdict] ?? verdict}
    </span>
  );
}

export default function ResultsTable({ connectorResults, breakdown }: Props) {
  const entries = Object.entries(connectorResults);

  if (entries.length === 0) {
    return <p className="text-sm text-gray-600 italic">Sin resultados de conectores.</p>;
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-gray-800">
      <table className="w-full text-sm">
        <thead className="bg-gray-900 text-gray-400 text-xs uppercase tracking-wider">
          <tr>
            <th className="px-4 py-2.5 text-left">Fuente</th>
            <th className="px-4 py-2.5 text-left">Hallazgo</th>
            <th className="px-4 py-2.5 text-left">Veredicto</th>
            <th className="px-4 py-2.5 text-right">Puntos</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/60">
          {entries.map(([name, result]) => (
            <tr key={name} className="hover:bg-gray-900/40 transition">
              {/* Fuente */}
              <td className="px-4 py-3 font-medium text-gray-200 flex items-center gap-2">
                {result.success ? (
                  <CheckCircle2 size={14} className="text-green-500 shrink-0" />
                ) : result.error === "missing_api_key" || result.error === "unsupported_ioc_type" ? (
                  <AlertCircle size={14} className="text-gray-600 shrink-0" />
                ) : (
                  <XCircle size={14} className="text-red-500 shrink-0" />
                )}
                {SOURCE_LABEL[name] ?? name}
              </td>

              {/* Hallazgo clave */}
              <td className="px-4 py-3 text-gray-400">
                <KeyFinding result={result} />
              </td>

              {/* Veredicto */}
              <td className="px-4 py-3">
                <VerdictBadge verdict={result.verdict} />
              </td>

              {/* Puntos de scoring */}
              <td className="px-4 py-3 text-right tabular-nums font-mono text-xs">
                {breakdown[name] !== undefined ? (
                  <span className={breakdown[name] > 0 ? "text-red-400" : breakdown[name] < 0 ? "text-green-400" : "text-gray-600"}>
                    {breakdown[name] > 0 ? "+" : ""}{breakdown[name]}
                  </span>
                ) : (
                  <span className="text-gray-700">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
