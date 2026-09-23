import type { ReactNode } from "react";
import { Globe, Server, Shield, FileSearch, Link } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ConnectorResult } from "@/api/client";

interface Props {
  connectorResults: Record<string, ConnectorResult>;
  breakdown: Record<string, number>;
  iocType?: string;
}

const SOURCE_LABEL: Record<string, string> = {
  virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", shodan: "Shodan",
  otx: "OTX", malwarebazaar: "MalwareBazaar", urlhaus: "URLhaus",
  urlscan: "URLScan", threatfox: "ThreatFox", ipinfo: "IPinfo",
  securitytrails: "SecurityTrails", hybrid_analysis: "Hybrid Analysis",
  netlas: "Netlas", criminal_ip: "Criminal IP", malshare: "MalShare",
  pulsedive: "Pulsedive", censys: "Censys", rdap: "RDAP",
};

const VERDICT_DOT: Record<string, string> = {
  malicious: "bg-orange-500", suspicious: "bg-yellow-400",
  clean: "bg-emerald-500", unknown: "bg-gray-700", error: "bg-red-700", info: "bg-purple-500",
};

const VERDICT_SCORE: Record<string, string> = {
  malicious: "text-orange-400", suspicious: "text-yellow-400",
  clean: "text-emerald-500", unknown: "text-gray-600",
};

type Group = { label: string; icon: ReactNode; connectors: string[] };

const GROUPS: Record<string, Group[]> = {
  ipv4: [
    { label: "Reputación", icon: <Shield size={10} />, connectors: ["virustotal","abuseipdb","otx","threatfox","pulsedive"] },
    { label: "Infraestructura", icon: <Server size={10} />, connectors: ["shodan","netlas","censys","ipinfo","criminal_ip"] },
  ],
  ipv6: [
    { label: "Reputación", icon: <Shield size={10} />, connectors: ["virustotal","abuseipdb","otx","pulsedive"] },
    { label: "Info de IP", icon: <Globe size={10} />, connectors: ["ipinfo"] },
  ],
  domain: [
    { label: "Análisis web", icon: <Globe size={10} />, connectors: ["virustotal","urlscan","urlhaus","otx","threatfox"] },
    { label: "Registro", icon: <Link size={10} />, connectors: ["rdap","securitytrails"] },
    { label: "TI", icon: <Shield size={10} />, connectors: ["pulsedive"] },
  ],
  url: [
    { label: "Análisis web", icon: <Globe size={10} />, connectors: ["virustotal","urlscan","urlhaus","otx","threatfox"] },
    { label: "TI", icon: <Shield size={10} />, connectors: ["pulsedive"] },
  ],
  md5: hashGroups(), sha1: hashGroups(), sha256: hashGroups(),
};

function hashGroups(): Group[] {
  return [
    { label: "Análisis de malware", icon: <FileSearch size={10} />, connectors: ["virustotal","malwarebazaar","hybrid_analysis","malshare"] },
    { label: "TI", icon: <Shield size={10} />, connectors: ["threatfox","otx","pulsedive"] },
  ];
}

function KeyFinding({ result }: { result: ConnectorResult }) {
  const d = result.data;
  if (!result.success) return <span className="text-gray-700">{result.error ?? "—"}</span>;
  if (result.source === "virustotal")      return <>{(d.malicious as number ?? 0)}/{(d.total as number ?? 0)} engines</>;
  if (result.source === "abuseipdb")       return <>{d.confidence as number ?? 0}% conf · {d.total_reports as number ?? 0} reports</>;
  if (result.source === "shodan")          return <>{((d.open_ports as number[]) ?? []).join(", ") || "no open ports"}</>;
  if (result.source === "otx")             return <>{d.pulse_count as number ?? 0} pulses</>;
  if (result.source === "malwarebazaar")   return <>{d.found ? "known hash" : "not found"}</>;
  if (result.source === "urlhaus")         return <>{d.found ? "known url" : "not found"}</>;
  if (result.source === "urlscan")         return <>{d.found ? `${d.malicious_count ?? 0} malicious scans` : "no scans"}</>;
  if (result.source === "threatfox")       return <>{d.found ? (d.malware as string) : "not found"}</>;
  if (result.source === "ipinfo")          return <>{[d.is_tor && "tor", d.is_vpn && "vpn", d.is_proxy && "proxy"].filter(Boolean).join(" ") || (d.org as string) || "—"}</>;
  if (result.source === "hybrid_analysis") return <>{d.found ? (d.vx_family as string || `threat lvl ${d.threat_level}`) : "not found"}</>;
  if (result.source === "rdap")            return <>{d.found ? (d.days_old != null ? `${d.days_old}d old` : "?") : "no data"}</>;
  if (result.source === "securitytrails")  return <>{d.days_old != null ? `${d.days_old}d` : "—"}</>;
  if (result.source === "netlas")          return <>{((d.sensitive_ports ?? d.open_ports) as number[] ?? []).join(", ") || "—"}</>;
  if (result.source === "criminal_ip")     return <>{(d.worst_score ?? d.score) as string || "—"}</>;
  if (result.source === "malshare")        return <>{d.found ? "known" : "not found"}</>;
  if (result.source === "pulsedive")       return <>{(d.risk as string) || "—"}</>;
  if (result.source === "censys")          return <>{((d.sensitive_ports ?? d.open_ports) as number[] ?? []).join(", ") || "—"}</>;
  return <>—</>;
}

function isInactive(r: ConnectorResult) {
  return r.error === "missing_api_key" || r.error === "unsupported_ioc_type";
}

function Row({ name, result, points }: { name: string; result: ConnectorResult; points?: number }) {
  const inactive = isInactive(result);
  return (
    <div className={cn(
      "grid items-center gap-2 py-1.5 px-2 rounded transition-colors",
      "hover:bg-white/[0.03]",
      inactive && "opacity-30",
    )}
    style={{ gridTemplateColumns: "8px 1fr auto auto" }}>
      <div className={cn("w-1.5 h-1.5 rounded-full shrink-0", inactive ? "bg-gray-800" : (VERDICT_DOT[result.verdict] ?? "bg-gray-700"))} />
      <div className="flex items-center gap-3 min-w-0">
        <span className="font-data text-xs text-gray-300 w-[100px] shrink-0">{SOURCE_LABEL[name] ?? name}</span>
        {!inactive && <span className="font-data text-xs text-gray-600 truncate"><KeyFinding result={result} /></span>}
      </div>
      {!inactive && points !== undefined && points !== 0 && (
        <span className={cn("font-data text-xs font-semibold", points > 0 ? "text-red-400" : "text-emerald-400")}>
          {points > 0 ? "+" : ""}{points}
        </span>
      )}
      {(inactive || !points) && <span />}
    </div>
  );
}

function GroupBlock({ group, connectorResults, breakdown }: {
  group: Group; connectorResults: Record<string, ConnectorResult>; breakdown: Record<string, number>;
}) {
  const rows = group.connectors.filter(c => connectorResults[c]);
  if (!rows.length) return null;
  const active = rows.filter(c => !isInactive(connectorResults[c]));
  const inactive = rows.filter(c => isInactive(connectorResults[c]));
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-1 px-2">
        <span className="text-gray-700">{group.icon}</span>
        <span className="text-[9px] uppercase tracking-[0.15em] text-gray-700 font-medium">{group.label}</span>
      </div>
      {[...active, ...inactive].map(n => <Row key={n} name={n} result={connectorResults[n]} points={breakdown[n]} />)}
    </div>
  );
}

export default function ResultsTable({ connectorResults, breakdown, iocType }: Props) {
  const groups = iocType ? GROUPS[iocType] : null;
  const entries = Object.entries(connectorResults).filter(([k]) => k !== "__pcap_data__");
  if (!entries.length) return null;

  if (groups) {
    const covered = new Set(groups.flatMap(g => g.connectors));
    const rest = entries.map(([k]) => k).filter(k => !covered.has(k));
    return (
      <div className="space-y-3">
        {groups.map(g => <GroupBlock key={g.label} group={g} connectorResults={connectorResults} breakdown={breakdown} />)}
        {rest.length > 0 && <GroupBlock group={{ label: "Otras", icon: <Shield size={10} />, connectors: rest }} connectorResults={connectorResults} breakdown={breakdown} />}
      </div>
    );
  }

  return (
    <div className="space-y-0.5">
      {entries.sort(([,a],[,b]) => (isInactive(a)?1:0)-(isInactive(b)?1:0))
        .map(([n,r]) => <Row key={n} name={n} result={r} points={breakdown[n]} />)}
    </div>
  );
}
