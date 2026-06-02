import { useQuery } from "@tanstack/react-query";
import { CircleDot } from "lucide-react";
import { getSources } from "@/api/client";
import { cn } from "@/lib/utils";

const SOURCE_LABEL: Record<string, string> = {
  virustotal:      "VirusTotal",
  abuseipdb:       "AbuseIPDB",
  shodan:          "Shodan",
  otx:             "AlienVault OTX",
  malwarebazaar:   "MalwareBazaar",
  urlhaus:         "URLhaus",
  urlscan:         "URLScan.io",
  threatfox:       "ThreatFox",
  ipinfo:          "IPinfo",
  securitytrails:  "SecurityTrails",
  hybrid_analysis: "Hybrid Analysis",
  netlas:          "Netlas",
  criminal_ip:     "Criminal IP",
  malshare:        "MalShare",
  pulsedive:       "Pulsedive",
  censys:          "Censys",
  rdap:            "RDAP / WHOIS",
};

// Grupos en orden de visualización
const GROUPS: { label: string; names: string[] }[] = [
  {
    label: "Threat Intelligence",
    names: ["virustotal", "otx", "threatfox", "pulsedive"],
  },
  {
    label: "Análisis de IPs",
    names: ["abuseipdb", "shodan", "ipinfo", "criminal_ip", "netlas", "censys"],
  },
  {
    label: "Dominios & URLs",
    names: ["urlscan", "urlhaus", "rdap", "securitytrails"],
  },
  {
    label: "Hashes & Malware",
    names: ["malwarebazaar", "hybrid_analysis", "malshare"],
  },
];

export default function SourcesStatus() {
  const { data } = useQuery({
    queryKey: ["sources"],
    queryFn: getSources,
    staleTime: 60_000,
  });

  if (!data) return null;

  const byName = Object.fromEntries(data.map((s) => [s.name, s]));
  const active = data.filter((s) => s.available).length;
  const total  = data.length;

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/50 px-4 py-3 space-y-3">
      <p className="text-xs text-gray-500">
        Fuentes activas: <span className="text-gray-300 font-medium">{active}/{total}</span>
      </p>

      {GROUPS.map((group) => {
        const sources = group.names
          .map((n) => byName[n])
          .filter(Boolean)
          // activas primero, inactivas al final
          .sort((a, b) => (b.available ? 1 : 0) - (a.available ? 1 : 0));

        if (sources.length === 0) return null;

        return (
          <div key={group.label}>
            <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1.5">
              {group.label}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {sources.map((s) => (
                <span
                  key={s.name}
                  className={cn(
                    "flex items-center gap-1 text-xs rounded-full px-2.5 py-0.5 border",
                    s.available
                      ? "border-green-900 bg-green-950/50 text-green-400"
                      : "border-gray-800 bg-gray-900 text-gray-600"
                  )}
                >
                  <CircleDot size={8} />
                  {SOURCE_LABEL[s.name] ?? s.name}
                </span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
