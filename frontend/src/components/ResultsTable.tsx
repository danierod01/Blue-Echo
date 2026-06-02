import type { ReactNode } from "react";
import { CheckCircle2, XCircle, AlertCircle, Globe, Server, Shield, FileSearch, Link } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ConnectorResult } from "@/api/client";

interface Props {
  connectorResults: Record<string, ConnectorResult>;
  breakdown: Record<string, number>;
  iocType?: string;
}

const SOURCE_LABEL: Record<string, string> = {
  virustotal:       "VirusTotal",
  abuseipdb:        "AbuseIPDB",
  shodan:           "Shodan",
  otx:              "AlienVault OTX",
  malwarebazaar:    "MalwareBazaar",
  urlhaus:          "URLhaus",
  urlscan:          "URLScan.io",
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
  pcap_analyzer:    "PCAP Analyzer",
};

const VERDICT_BADGE: Record<string, string> = {
  malicious:  "bg-orange-500/15 text-orange-300 border-orange-500/30",
  suspicious: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
  clean:      "bg-green-500/15  text-green-300  border-green-500/30",
  unknown:    "bg-gray-500/15   text-gray-400   border-gray-500/30",
  error:      "bg-red-500/15    text-red-400    border-red-500/30",
  info:       "bg-purple-500/15 text-purple-300 border-purple-500/30",
};

const VERDICT_LABELS: Record<string, string> = {
  malicious: "Malicioso", suspicious: "Sospechoso",
  clean: "Limpio", unknown: "Desconocido", error: "Error", info: "Info",
};

// Agrupación por tipo de IOC
type Group = { label: string; icon: ReactNode; connectors: string[] };

const GROUPS: Record<string, Group[]> = {
  ipv4: [
    { label: "Reputación & Threat Intelligence", icon: <Shield size={13} />,
      connectors: ["virustotal", "abuseipdb", "otx", "threatfox", "pulsedive"] },
    { label: "Infraestructura de red", icon: <Server size={13} />,
      connectors: ["shodan", "netlas", "censys", "ipinfo", "criminal_ip"] },
  ],
  ipv6: [
    { label: "Reputación & Threat Intelligence", icon: <Shield size={13} />,
      connectors: ["virustotal", "abuseipdb", "otx", "threatfox", "pulsedive"] },
    { label: "Información de IP", icon: <Globe size={13} />,
      connectors: ["ipinfo"] },
  ],
  domain: [
    { label: "Análisis web & URL", icon: <Globe size={13} />,
      connectors: ["virustotal", "urlscan", "urlhaus", "otx", "threatfox"] },
    { label: "Registro & DNS", icon: <Link size={13} />,
      connectors: ["rdap", "securitytrails"] },
    { label: "Threat Intelligence", icon: <Shield size={13} />,
      connectors: ["pulsedive"] },
  ],
  url: [
    { label: "Análisis web & URL", icon: <Globe size={13} />,
      connectors: ["virustotal", "urlscan", "urlhaus", "otx", "threatfox"] },
    { label: "Threat Intelligence", icon: <Shield size={13} />,
      connectors: ["pulsedive"] },
  ],
  md5:    hashGroups(),
  sha1:   hashGroups(),
  sha256: hashGroups(),
};

function hashGroups(): Group[] {
  return [
    { label: "Análisis de malware", icon: <FileSearch size={13} />,
      connectors: ["virustotal", "malwarebazaar", "hybrid_analysis", "malshare"] },
    { label: "Threat Intelligence", icon: <Shield size={13} />,
      connectors: ["threatfox", "otx", "pulsedive"] },
  ];
}

function KeyFinding({ result }: { result: ConnectorResult }) {
  const d = result.data;
  if (!result.success) return <span className="text-gray-600 italic">{result.error ?? "error"}</span>;
  if (result.source === "virustotal")      return <span>{(d.malicious as number ?? 0)}/{(d.total as number ?? 0)} motores</span>;
  if (result.source === "abuseipdb")       return <span>Confianza {d.confidence as number ?? 0}% · {d.total_reports as number ?? 0} reportes</span>;
  if (result.source === "shodan")          return <span>{((d.open_ports as number[]) ?? []).join(", ") || "Sin puertos"}</span>;
  if (result.source === "otx")             return <span>{d.pulse_count as number ?? 0} pulsos</span>;
  if (result.source === "malwarebazaar")   return <span>{d.found ? "Hash conocido" : "No encontrado"}</span>;
  if (result.source === "urlhaus")         return <span>{d.found ? "URL conocida" : "No encontrada"}</span>;
  if (result.source === "urlscan")         return <span>{d.found ? `${d.malicious_count ?? 0} escaneos maliciosos` : "Sin escaneos previos"}</span>;
  if (result.source === "threatfox")       return <span>{d.found ? (d.malware as string) : "No encontrado"}</span>;
  if (result.source === "ipinfo")          return <span>{[d.is_tor && "Tor", d.is_vpn && "VPN", d.is_proxy && "Proxy"].filter(Boolean).join(", ") || (d.org as string) || "—"}</span>;
  if (result.source === "hybrid_analysis") return <span>{d.found ? (d.vx_family as string || `score ${d.threat_score}`) : "No encontrado"}</span>;
  if (result.source === "rdap")            return <span>{d.found ? (d.days_old != null ? `${d.days_old} días` : "Fecha desconocida") : "Sin datos RDAP"}</span>;
  if (result.source === "securitytrails")  return <span>{d.days_old != null ? `${d.days_old} días` : "—"}</span>;
  if (result.source === "netlas")          return <span>{((d.sensitive_ports ?? d.open_ports) as number[] ?? []).join(", ") || "Sin puertos"}</span>;
  if (result.source === "criminal_ip")     return <span className="capitalize">{(d.worst_score ?? d.score) as string || "—"}</span>;
  if (result.source === "malshare")        return <span>{d.found ? "Hash conocido" : "No encontrado"}</span>;
  if (result.source === "pulsedive")       return <span className="capitalize">{(d.risk as string) || "—"}</span>;
  if (result.source === "censys")          return <span>{((d.sensitive_ports ?? d.open_ports) as number[] ?? []).join(", ") || "Sin puertos"}</span>;
  return <span className="text-gray-500">—</span>;
}

function isInactive(r: ConnectorResult) {
  return r.error === "missing_api_key" || r.error === "unsupported_ioc_type";
}

const VERDICT_LEFT_BORDER: Record<string, string> = {
  malicious:  "border-l-orange-500",
  suspicious: "border-l-yellow-500",
  clean:      "border-l-green-600",
  unknown:    "border-l-gray-700",
  error:      "border-l-red-700",
  info:       "border-l-purple-600",
};

function ConnectorCard({
  name, result, points, index,
}: { name: string; result: ConnectorResult; points: number | undefined; index: number }) {
  const inactive = isInactive(result);
  const badgeClass = VERDICT_BADGE[result.verdict] ?? VERDICT_BADGE.unknown;
  const leftBorder = inactive ? "border-l-gray-800" : (VERDICT_LEFT_BORDER[result.verdict] ?? "border-l-gray-700");

  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-xl border border-l-2 px-4 py-3 transition-all duration-200",
        leftBorder,
        inactive
          ? "border-gray-800/40 bg-gray-900/20 opacity-40"
          : "border-gray-800/60 bg-gray-900/40 hover:bg-gray-800/60 hover:scale-[1.005] hover:shadow-sm"
      )}
      style={{ animationDelay: `${index * 50}ms` }}
    >
      {/* Status icon */}
      <span className="shrink-0">
        {result.success
          ? <CheckCircle2 size={14} className="text-green-500" />
          : inactive
            ? <AlertCircle size={14} className="text-gray-700" />
            : <XCircle size={14} className="text-red-500" />}
      </span>

      {/* Name + finding */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={cn("text-sm font-medium", inactive ? "text-gray-600" : "text-gray-200")}>
            {SOURCE_LABEL[name] ?? name}
          </span>
          {!inactive && (
            <span className={cn("text-[10px] font-semibold border rounded-full px-2 py-0.5", badgeClass)}>
              {VERDICT_LABELS[result.verdict] ?? result.verdict}
            </span>
          )}
        </div>
        {!inactive && (
          <div className="text-xs text-gray-500 mt-0.5 truncate">
            <KeyFinding result={result} />
          </div>
        )}
      </div>

      {/* Score */}
      {points !== undefined && points !== 0 && (
        <span className={cn(
          "text-xs font-mono font-bold tabular-nums shrink-0",
          points > 0 ? "text-red-400" : "text-green-400"
        )}>
          {points > 0 ? "+" : ""}{points}
        </span>
      )}
    </div>
  );
}

function GroupSection({ group, connectorResults, breakdown, index: groupIndex }: {
  group: Group;
  connectorResults: Record<string, ConnectorResult>;
  breakdown: Record<string, number>;
  index: number;
}) {
  const matching = group.connectors.filter((c) => connectorResults[c]);
  if (matching.length === 0) return null;

  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-4">
      <div className="flex items-center gap-1.5 text-xs text-gray-500 uppercase tracking-wider mb-3">
        <span className="text-gray-600">{group.icon}</span>
        {group.label}
      </div>
      <div className="flex flex-col gap-1.5">
        {matching.map((name, i) => (
          <ConnectorCard
            key={name}
            name={name}
            result={connectorResults[name]}
            points={breakdown[name]}
            index={groupIndex * 5 + i}
          />
        ))}
      </div>
    </div>
  );
}

export default function ResultsTable({ connectorResults, breakdown, iocType }: Props) {
  const groups = iocType ? GROUPS[iocType] : null;

  if (Object.keys(connectorResults).length === 0) {
    return <p className="text-sm text-gray-600 italic">Sin resultados de conectores.</p>;
  }

  // Vista agrupada por tipo de IOC
  if (groups) {
    const coveredConnectors = new Set(groups.flatMap((g) => g.connectors));
    const uncovered = Object.keys(connectorResults).filter((k) => !coveredConnectors.has(k) && k !== "__pcap_data__");

    return (
      <div className="flex flex-col gap-3">
        {groups.map((group, i) => (
          <GroupSection
            key={group.label}
            group={group}
            connectorResults={connectorResults}
            breakdown={breakdown}
            index={i}
          />
        ))}
        {/* Conectores que no encajan en ningún grupo (por si hay nuevas fuentes) */}
        {uncovered.length > 0 && (
          <GroupSection
            group={{ label: "Otras fuentes", icon: <Shield size={13} />, connectors: uncovered }}
            connectorResults={connectorResults}
            breakdown={breakdown}
            index={groups.length}
          />
        )}
      </div>
    );
  }

  // Fallback: vista plana ordenada (para tipos no mapeados o historial antiguo)
  const entries = Object.entries(connectorResults)
    .filter(([k]) => k !== "__pcap_data__")
    .sort(([, a], [, b]) => (isInactive(a) ? 1 : 0) - (isInactive(b) ? 1 : 0));

  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-4">
      <div className="flex flex-col gap-1.5">
        {entries.map(([name, result], i) => (
          <ConnectorCard key={name} name={name} result={result} points={breakdown[name]} index={i} />
        ))}
      </div>
    </div>
  );
}
