import { CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { cn, VERDICT_COLOR } from "@/lib/utils";
import type { ConnectorResult } from "@/api/client";

interface Props {
  connectorResults: Record<string, ConnectorResult>;
  breakdown: Record<string, number>;
}

const SOURCE_LABEL: Record<string, string> = {
  virustotal:       "VirusTotal",
  abuseipdb:        "AbuseIPDB",
  shodan:           "Shodan",
  otx:              "AlienVault OTX",
  malwarebazaar:    "MalwareBazaar",
  urlhaus:          "URLhaus",
  threatfox:        "ThreatFox",
  ipinfo:           "IPinfo",
  securitytrails:   "SecurityTrails",
  hybrid_analysis:  "Hybrid Analysis",
  netlas:           "Netlas",
  criminal_ip:      "Criminal IP",
  malshare:         "MalShare",
  pulsedive:        "Pulsedive",
  censys:           "Censys",
  rdap:             "RDAP / WHOIS",
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
  if (result.source === "urlhaus") {
    return <span>{d.found ? "URL conocida" : "No encontrada"}</span>;
  }
  if (result.source === "threatfox") {
    return <span>{d.found ? (d.malware as string) : "No encontrado"}</span>;
  }
  if (result.source === "ipinfo") {
    const flags = [
      d.is_tor && "Tor",
      d.is_vpn && "VPN",
      d.is_proxy && "Proxy",
    ].filter(Boolean).join(", ");
    return <span>{flags || (d.org as string) || "—"}</span>;
  }
  if (result.source === "hybrid_analysis") {
    return <span>{d.found ? (d.vx_family as string || `score ${d.threat_score}`) : "No encontrado"}</span>;
  }
  if (result.source === "rdap") {
    if (!d.found) return <span className="text-gray-500">Sin datos RDAP</span>;
    const age = d.days_old as number | null;
    return <span>{age !== null && age !== undefined ? `${age} días de antigüedad` : "Fecha desconocida"}</span>;
  }
  if (result.source === "securitytrails") {
    const age = d.days_old as number | null;
    return <span>{age !== null && age !== undefined ? `${age} días de antigüedad` : "—"}</span>;
  }
  if (result.source === "netlas") {
    const ports = (d.sensitive_ports as number[] ?? d.open_ports as number[] ?? []).join(", ");
    return <span>{ports || "Sin puertos sensibles"}</span>;
  }
  if (result.source === "criminal_ip") {
    const score = (d.worst_score as string) || (d.score as string) || "—";
    return <span className="capitalize">{score}</span>;
  }
  if (result.source === "malshare") {
    return <span>{d.found ? "Hash conocido" : "No encontrado"}</span>;
  }
  if (result.source === "pulsedive") {
    const risk = (d.risk as string) || "—";
    return <span className="capitalize">{risk}</span>;
  }
  if (result.source === "censys") {
    const ports = (d.sensitive_ports as number[] ?? d.open_ports as number[] ?? []).join(", ");
    return <span>{ports || "Sin puertos sensibles"}</span>;
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

function isInactive(result: ConnectorResult) {
  return result.error === "missing_api_key" || result.error === "unsupported_ioc_type";
}

export default function ResultsTable({ connectorResults, breakdown }: Props) {
  const entries = Object.entries(connectorResults).sort(([, a], [, b]) => {
    const aInactive = isInactive(a) ? 1 : 0;
    const bInactive = isInactive(b) ? 1 : 0;
    return aInactive - bInactive;
  });

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
