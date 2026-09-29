import { useQuery } from "@tanstack/react-query";
import { CircleDot } from "lucide-react";
import { getSources } from "@/api/client";
import { cn } from "@/lib/utils";

const SOURCE_LABEL: Record<string, string> = {
  virustotal:      "VirusTotal",
  abuseipdb:       "AbuseIPDB",
  shodan:          "Shodan",
  greynoise:       "GreyNoise",
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
    names: ["abuseipdb", "shodan", "greynoise", "ipinfo", "criminal_ip", "netlas", "censys"],
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
    <div className="soc-panel px-4 py-3 space-y-3">
      <div className="flex items-center justify-between">
        <span className="soc-label">Fuentes de inteligencia</span>
        <span className="font-data text-xs text-slate-400">
          <span className="text-accent font-semibold">{active}</span>/{total} activas
        </span>
      </div>

      {GROUPS.map((group) => {
        const sources = group.names
          .map((n) => byName[n])
          .filter(Boolean)
          // activas primero, inactivas al final
          .sort((a, b) => (b.available ? 1 : 0) - (a.available ? 1 : 0));

        if (sources.length === 0) return null;

        return (
          <div key={group.label}>
            <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">
              {group.label}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {sources.map((s) => (
                <span
                  key={s.name}
                  className={cn(
                    "flex items-center gap-1 font-data text-[11px] rounded-full px-2.5 py-0.5 border",
                    s.available
                      ? "border-accent/30 bg-accent/10 text-accent-soft"
                      : "border-slate-800 bg-slate-900/60 text-slate-600"
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
