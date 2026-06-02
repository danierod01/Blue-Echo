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
  virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", shodan: "Shodan",
  otx: "AlienVault OTX", malwarebazaar: "MalwareBazaar", urlhaus: "URLhaus",
  urlscan: "URLScan.io", threatfox: "ThreatFox", ipinfo: "IPinfo",
  securitytrails: "SecurityTrails", hybrid_analysis: "Hybrid Analysis",
  netlas: "Netlas", criminal_ip: "Criminal IP", malshare: "MalShare",
  pulsedive: "Pulsedive", censys: "Censys", rdap: "RDAP / WHOIS",
  pcap_analyzer: "PCAP Analyzer",
};

const VERDICT_COLORS: Record<string, { dot: string; text: string; bar: string }> = {
  malicious:  { dot: "bg-orange-500", text: "text-orange-400", bar: "bg-orange-500/20" },
  suspicious: { dot: "bg-yellow-500", text: "text-yellow-400", bar: "bg-yellow-500/20" },
  clean:      { dot: "bg-green-500",  text: "text-green-400",  bar: "bg-green-500/10" },
  unknown:    { dot: "bg-gray-600",   text: "text-gray-500",   bar: "" },
  error:      { dot: "bg-red-600",    text: "text-red-500",    bar: "" },
  info:       { dot: "bg-purple-500", text: "text-purple-400", bar: "bg-purple-500/10" },
};

type Group = { label: string; icon: ReactNode; connectors: string[] };

const GROUPS: Record<string, Group[]> = {
  ipv4: [
    { label: "Reputación & Threat Intelligence", icon: <Shield size={12} />, connectors: ["virustotal","abuseipdb","otx","threatfox","pulsedive"] },
    { label: "Infraestructura de red", icon: <Server size={12} />, connectors: ["shodan","netlas","censys","ipinfo","criminal_ip"] },
  ],
  ipv6: [
    { label: "Reputación & Threat Intelligence", icon: <Shield size={12} />, connectors: ["virustotal","abuseipdb","otx","threatfox","pulsedive"] },
    { label: "Información de IP", icon: <Globe size={12} />, connectors: ["ipinfo"] },
  ],
  domain: [
    { label: "Análisis web & URL", icon: <Globe size={12} />, connectors: ["virustotal","urlscan","urlhaus","otx","threatfox"] },
    { label: "Registro & DNS", icon: <Link size={12} />, connectors: ["rdap","securitytrails"] },
    { label: "Threat Intelligence", icon: <Shield size={12} />, connectors: ["pulsedive"] },
  ],
  url: [
    { label: "Análisis web & URL", icon: <Globe size={12} />, connectors: ["virustotal","urlscan","urlhaus","otx","threatfox"] },
    { label: "Threat Intelligence", icon: <Shield size={12} />, connectors: ["pulsedive"] },
  ],
  md5:    hashGroups(),
  sha1:   hashGroups(),
  sha256: hashGroups(),
};

function hashGroups(): Group[] {
  return [
    { label: "Análisis de malware", icon: <FileSearch size={12} />, connectors: ["virustotal","malwarebazaar","hybrid_analysis","malshare"] },
    { label: "Threat Intelligence", icon: <Shield size={12} />, connectors: ["threatfox","otx","pulsedive"] },
  ];
}

function KeyFinding({ result }: { result: ConnectorResult }) {
  const d = result.data;
  if (!result.success) return <span className="text-gray-700 italic">{result.error ?? "error"}</span>;
  if (result.source === "virustotal")      return <span>{(d.malicious as number ?? 0)}/{(d.total as number ?? 0)} motores</span>;
  if (result.source === "abuseipdb")       return <span>Confianza {d.confidence as number ?? 0}% · {d.total_reports as number ?? 0} reportes</span>;
  if (result.source === "shodan")          return <span>{((d.open_ports as number[]) ?? []).join(", ") || "Sin puertos"}</span>;
  if (result.source === "otx")             return <span>{d.pulse_count as number ?? 0} pulsos</span>;
  if (result.source === "malwarebazaar")   return <span>{d.found ? "Hash conocido" : "No encontrado"}</span>;
  if (result.source === "urlhaus")         return <span>{d.found ? "URL conocida" : "No encontrada"}</span>;
  if (result.source === "urlscan")         return <span>{d.found ? `${d.malicious_count ?? 0} escaneos maliciosos` : "Sin escaneos"}</span>;
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
  return <span className="text-gray-600">—</span>;
}

function isInactive(r: ConnectorResult) {
  return r.error === "missing_api_key" || r.error === "unsupported_ioc_type";
}

function ConnectorRow({ name, result, points }: { name: string; result: ConnectorResult; points?: number }) {
  const inactive = isInactive(result);
  const vc = inactive ? null : (VERDICT_COLORS[result.verdict] ?? VERDICT_COLORS.unknown);

  if (inactive) {
    return (
      <div className="flex items-center gap-3 py-2 px-3 rounded-lg opacity-30">
        <AlertCircle size={12} className="text-gray-700 shrink-0" />
        <span className="text-xs text-gray-700">{SOURCE_LABEL[name] ?? name}</span>
      </div>
    );
  }

  return (
    <div className={cn(
      "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-150 group cursor-default",
      vc?.bar,
      "hover:brightness-110"
    )}>
      {/* Indicador */}
      <div className={cn("w-1.5 h-1.5 rounded-full shrink-0", vc?.dot ?? "bg-gray-600")} />

      {/* Nombre */}
      <span className="text-sm font-medium text-gray-200 flex-1 min-w-0 truncate">
        {SOURCE_LABEL[name] ?? name}
      </span>

      {/* Hallazgo */}
      <span className="text-xs text-gray-500 hidden sm:block truncate max-w-[140px]">
        <KeyFinding result={result} />
      </span>

      {/* Score */}
      {points !== undefined && points !== 0 && (
        <span className={cn(
          "text-xs font-mono font-bold shrink-0 ml-2",
          points > 0 ? "text-red-400" : "text-green-400"
        )}>
          {points > 0 ? "+" : ""}{points}
        </span>
      )}

      {/* Status icon */}
      <span className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
        {result.success
          ? <CheckCircle2 size={12} className="text-green-500" />
          : <XCircle size={12} className="text-red-500" />}
      </span>
    </div>
  );
}

function GroupSection({ group, connectorResults, breakdown }: {
  group: Group; connectorResults: Record<string, ConnectorResult>; breakdown: Record<string, number>;
}) {
  const active   = group.connectors.filter((c) => connectorResults[c] && !isInactive(connectorResults[c]));
  const inactive = group.connectors.filter((c) => connectorResults[c] && isInactive(connectorResults[c]));
  if (active.length + inactive.length === 0) return null;

  return (
    <div>
      <div className="flex items-center gap-1.5 mb-1.5 px-1">
        <span className="text-gray-600">{group.icon}</span>
        <span className="text-[10px] font-semibold text-gray-600 uppercase tracking-widest">{group.label}</span>
        <div className="flex-1 h-px bg-gray-800/60 ml-2" />
      </div>
      <div className="space-y-0.5">
        {active.map((n) => <ConnectorRow key={n} name={n} result={connectorResults[n]} points={breakdown[n]} />)}
        {inactive.map((n) => <ConnectorRow key={n} name={n} result={connectorResults[n]} />)}
      </div>
    </div>
  );
}

export default function ResultsTable({ connectorResults, breakdown, iocType }: Props) {
  const groups = iocType ? GROUPS[iocType] : null;
  const entries = Object.entries(connectorResults).filter(([k]) => k !== "__pcap_data__");
  if (entries.length === 0) return null;

  if (groups) {
    const covered = new Set(groups.flatMap((g) => g.connectors));
    const rest = entries.map(([k]) => k).filter((k) => !covered.has(k));
    return (
      <div className="space-y-4">
        {groups.map((g) => (
          <GroupSection key={g.label} group={g} connectorResults={connectorResults} breakdown={breakdown} />
        ))}
        {rest.length > 0 && (
          <GroupSection
            group={{ label: "Otras fuentes", icon: <Shield size={12} />, connectors: rest }}
            connectorResults={connectorResults} breakdown={breakdown}
          />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-0.5">
      {entries
        .sort(([,a],[,b]) => (isInactive(a)?1:0)-(isInactive(b)?1:0))
        .map(([n,r]) => <ConnectorRow key={n} name={n} result={r} points={breakdown[n]} />)
      }
    </div>
  );
}
