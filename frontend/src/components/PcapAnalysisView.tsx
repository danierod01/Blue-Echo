import ReactMarkdown from "react-markdown";
import { Network, FileSearch, Shield, Activity } from "lucide-react";
import type { PcapScanResponse } from "@/api/client";

interface Props {
  result: PcapScanResponse;
  onScanIoc?: (ioc: string) => void;
}

const IOC_COLORS: Record<string, string> = {
  ipv4:   "text-orange-400 border-orange-800/60 bg-orange-950/20",
  ipv6:   "text-orange-400 border-orange-800/60 bg-orange-950/20",
  domain: "text-blue-400  border-blue-800/60  bg-blue-950/20",
  url:    "text-blue-400  border-blue-800/60  bg-blue-950/20",
  md5:    "text-purple-400 border-purple-800/60 bg-purple-950/20",
  sha1:   "text-purple-400 border-purple-800/60 bg-purple-950/20",
  sha256: "text-purple-400 border-purple-800/60 bg-purple-950/20",
};

export default function PcapAnalysisView({ result, onScanIoc }: Props) {
  const { stats } = result;

  return (
    <div className="flex flex-col gap-6">

      {/* Cabecera */}
      <div className="rounded-2xl border border-purple-900/60 bg-gradient-to-br from-purple-950/40 to-gray-900 p-5">
        <div className="flex items-center gap-2 mb-1">
          <Network size={16} className="text-purple-400 shrink-0" />
          <h2 className="text-sm font-semibold text-purple-400 uppercase tracking-wider">
            Análisis PCAP
          </h2>
        </div>
        <p className="text-base font-mono text-white mt-1">{result.filename}</p>
        <div className="flex flex-wrap gap-4 mt-3 text-xs text-gray-400">
          <span>{stats.total_packets.toLocaleString()} paquetes</span>
          <span>{(stats.total_bytes / 1024).toFixed(1)} KB</span>
          <span>{result.total_iocs} IOCs extraídos</span>
        </div>
      </div>

      {/* Distribución de protocolos */}
      {Object.keys(stats.protocols).length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
          {Object.entries(stats.protocols)
            .sort(([, a], [, b]) => b - a)
            .map(([proto, count]) => (
              <div key={proto} className="rounded-xl border border-gray-800 bg-gray-900/50 p-3">
                <div className="flex items-center gap-1.5 mb-1">
                  <Activity size={12} className="text-gray-500" />
                  <p className="text-xs font-medium text-gray-400">{proto}</p>
                </div>
                <p className="text-xl font-bold text-white">{count.toLocaleString()}</p>
                <p className="text-xs text-gray-600">paquetes</p>
              </div>
            ))}
        </div>
      )}

      {/* Análisis IA */}
      <div className="rounded-2xl border border-blue-900/60 bg-gradient-to-br from-blue-950/40 to-gray-900 p-5">
        <div className="flex items-center gap-2 mb-3">
          <Shield size={16} className="text-blue-400 shrink-0" />
          <h2 className="text-sm font-semibold text-blue-400 uppercase tracking-wider">
            Análisis IA — Tráfico de Red
          </h2>
        </div>
        <div className="text-sm text-gray-200 leading-relaxed prose prose-invert prose-sm max-w-none
          [&_h2]:text-blue-300 [&_h2]:font-semibold [&_h2]:text-xs [&_h2]:uppercase [&_h2]:tracking-wider [&_h2]:mt-4 [&_h2]:mb-1 [&_h2:first-child]:mt-0
          [&_ul]:mt-1 [&_ul]:space-y-0.5 [&_li]:text-gray-300
          [&_strong]:text-white [&_code]:text-blue-300 [&_code]:bg-blue-950/50 [&_code]:px-1 [&_code]:rounded">
          <ReactMarkdown>{result.ai_summary}</ReactMarkdown>
        </div>
      </div>

      {/* Conexiones más activas */}
      {stats.top_connections.length > 0 && (
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-5">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
            Conexiones más activas
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-gray-300">
              <thead>
                <tr className="text-left text-gray-600 border-b border-gray-800">
                  <th className="pb-2 pr-4 font-medium">Origen</th>
                  <th className="pb-2 pr-4 font-medium">Destino</th>
                  <th className="pb-2 text-right font-medium">Paquetes</th>
                </tr>
              </thead>
              <tbody>
                {stats.top_connections.map((conn, i) => (
                  <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="py-1.5 pr-4 font-mono">{conn.src}</td>
                    <td className="py-1.5 pr-4 font-mono">{conn.dst}</td>
                    <td className="py-1.5 text-right tabular-nums">{conn.packets}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* DNS / HTTP / TLS SNI */}
      {(stats.dns_queries.length > 0 || stats.http_hosts.length > 0 || stats.tls_sni.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {stats.dns_queries.length > 0 && (
            <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                Consultas DNS ({stats.dns_queries.length})
              </h3>
              <ul className="space-y-1">
                {stats.dns_queries.slice(0, 15).map((q) => (
                  <li key={q} className="text-xs font-mono text-gray-300 truncate" title={q}>{q}</li>
                ))}
              </ul>
            </div>
          )}
          {stats.http_hosts.length > 0 && (
            <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                HTTP Hosts ({stats.http_hosts.length})
              </h3>
              <ul className="space-y-1">
                {stats.http_hosts.slice(0, 15).map((h) => (
                  <li key={h} className="text-xs font-mono text-gray-300 truncate" title={h}>{h}</li>
                ))}
              </ul>
            </div>
          )}
          {stats.tls_sni.length > 0 && (
            <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                TLS SNI ({stats.tls_sni.length})
              </h3>
              <ul className="space-y-1">
                {stats.tls_sni.slice(0, 15).map((s) => (
                  <li key={s} className="text-xs font-mono text-gray-300 truncate" title={s}>{s}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* IOCs extraídos */}
      {result.iocs_found.length > 0 && (
        <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-5">
          <div className="flex items-center gap-2 mb-3">
            <FileSearch size={16} className="text-gray-400 shrink-0" />
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
              IOCs extraídos del tráfico ({result.total_iocs})
            </h2>
          </div>
          <div className="flex flex-wrap gap-2">
            {result.iocs_found.map((ioc) => (
              <button
                key={ioc.value}
                onClick={() => onScanIoc?.(ioc.value)}
                title={onScanIoc ? `Escanear ${ioc.value}` : undefined}
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-mono transition-opacity ${
                  IOC_COLORS[ioc.ioc_type] ?? "text-gray-300 border-gray-700 bg-gray-800"
                } ${onScanIoc ? "cursor-pointer hover:opacity-70" : "cursor-default"}`}
              >
                <span className="opacity-60 text-[10px] uppercase">{ioc.ioc_type}</span>
                {ioc.value}
              </button>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}
