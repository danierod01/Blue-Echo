import { useState, useRef } from "react";
import { Loader2, Play, RotateCcw, Download } from "lucide-react";
import { Link } from "react-router-dom";
import { scanIoc, type ScanResponse } from "@/api/client";
import { VERDICT_COLOR } from "@/lib/utils";

interface BulkResult {
  ioc: string;
  status: "pending" | "running" | "done" | "error";
  data?: ScanResponse;
  errorMsg?: string;
}

interface Props {
  onComplete?: () => void;
}

const DELAY_MS = 2000;
const MAX_IOCS = 20;

const VERDICT_LABEL: Record<string, string> = {
  clean: "Limpio",
  suspicious: "Sospechoso",
  malicious: "Malicioso",
  critical: "Crítico",
};

export default function BulkScanPanel({ onComplete }: Props) {
  const [text, setText] = useState("");
  const [results, setResults] = useState<BulkResult[]>([]);
  const [running, setRunning] = useState(false);
  const abortRef = useRef(false);

  const iocList = text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, MAX_IOCS);

  const done = results.filter((r) => r.status === "done" || r.status === "error").length;
  const currentIoc = results.find((r) => r.status === "running")?.ioc ?? "";

  async function handleStart() {
    if (!iocList.length) return;
    abortRef.current = false;
    setRunning(true);
    setResults(iocList.map((ioc) => ({ ioc, status: "pending" })));

    for (let i = 0; i < iocList.length; i++) {
      if (abortRef.current) break;

      setResults((prev) =>
        prev.map((r, idx) => (idx === i ? { ...r, status: "running" } : r))
      );

      try {
        const data = await scanIoc(iocList[i]);
        setResults((prev) =>
          prev.map((r, idx) => (idx === i ? { ...r, status: "done", data } : r))
        );
      } catch (err) {
        setResults((prev) =>
          prev.map((r, idx) =>
            idx === i ? { ...r, status: "error", errorMsg: (err as Error).message } : r
          )
        );
      }

      if (i < iocList.length - 1) {
        await new Promise((res) => setTimeout(res, DELAY_MS));
      }
    }

    setRunning(false);
    onComplete?.();
  }

  function handleStop() {
    abortRef.current = true;
    setRunning(false);
  }

  function handleReset() {
    abortRef.current = true;
    setRunning(false);
    setResults([]);
    setText("");
  }

  function handleExportCsv() {
    const header = ["IOC", "Tipo", "Score", "Veredicto", "ID", "Error"];
    const rows = results.map((r) => [
      r.ioc,
      r.data?.ioc_type ?? "",
      r.data?.score?.toString() ?? "",
      r.data ? (VERDICT_LABEL[r.data.verdict] ?? r.data.verdict) : "",
      r.data?.id?.toString() ?? "",
      r.errorMsg ?? "",
    ]);
    // Prefijo con tab en celdas que empiecen por =, -, +, @ para prevenir inyección de fórmulas en Excel/Sheets
    const sanitize = (cell: string) =>
      /^[=\-+@]/.test(cell) ? `\t${cell}` : cell;
    const csv = [header, ...rows]
      .map((row) => row.map((cell) => `"${sanitize(cell).replace(/"/g, '""')}"`).join(","))
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bulk-scan-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Textarea de entrada */}
      {results.length === 0 && (
        <div className="flex flex-col gap-2">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={
              "Un IOC por línea (máx. 20):\n185.220.101.45\nmalware.evil.com\nd41d8cd98f00b204e9800998ecf8427e"
            }
            rows={6}
            className="w-full rounded-xl border border-gray-700 bg-gray-900 px-4 py-3 text-sm text-gray-100 placeholder-gray-600 outline-none focus:border-blue-500 transition resize-none font-mono"
          />
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-600">
              {iocList.length > 0
                ? `${iocList.length} IOC${iocList.length > 1 ? "s" : ""} detectado${iocList.length > 1 ? "s" : ""}${iocList.length === MAX_IOCS ? " (límite)" : ""}`
                : ""}
            </span>
            <button
              onClick={handleStart}
              disabled={iocList.length === 0}
              className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed transition"
            >
              <Play size={14} />
              Iniciar escaneo masivo
            </button>
          </div>
        </div>
      )}

      {/* Barra de progreso */}
      {running && (
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2 text-gray-400">
              <Loader2 size={14} className="animate-spin text-blue-500" />
              <span>
                Procesando {done + 1}/{results.length}
                {currentIoc && (
                  <span className="font-mono text-xs text-gray-500 ml-2">{currentIoc}</span>
                )}
              </span>
            </div>
            <button
              onClick={handleStop}
              className="text-xs text-gray-600 hover:text-red-400 transition"
            >
              Detener
            </button>
          </div>
          <div className="h-1.5 w-full rounded-full bg-gray-800">
            <div
              className="h-full rounded-full bg-blue-500 transition-all duration-500"
              style={{ width: `${(done / results.length) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Tabla de resultados */}
      {results.length > 0 && (
        <div className="flex flex-col gap-3">
          {!running && (
            <div className="flex justify-end gap-3">
              <button
                onClick={handleExportCsv}
                className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-green-400 transition"
              >
                <Download size={12} />
                Exportar CSV
              </button>
              <button
                onClick={handleReset}
                className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition"
              >
                <RotateCcw size={12} />
                Nuevo escaneo masivo
              </button>
            </div>
          )}
          <div className="overflow-x-auto rounded-xl border border-gray-800">
            <table className="w-full text-sm">
              <thead className="bg-gray-900 text-gray-400 text-xs uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-2.5 text-left">IOC</th>
                  <th className="px-4 py-2.5 text-left">Tipo</th>
                  <th className="px-4 py-2.5 text-right">Score</th>
                  <th className="px-4 py-2.5 text-left">Veredicto</th>
                  <th className="px-4 py-2.5 text-right">Detalle</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {results.map((r) => (
                  <tr key={r.ioc} className="hover:bg-gray-900/40 transition">
                    <td className="px-4 py-3 font-mono text-xs text-gray-300 max-w-[220px] truncate">
                      {r.ioc}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {r.data?.ioc_type ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums font-mono">
                      {r.status === "running" || r.status === "pending" ? (
                        r.status === "running" ? (
                          <Loader2 size={12} className="animate-spin text-blue-500 inline" />
                        ) : (
                          <span className="text-gray-700">—</span>
                        )
                      ) : r.status === "error" ? (
                        <span className="text-red-500 text-xs truncate max-w-[100px] block text-right">
                          {r.errorMsg}
                        </span>
                      ) : (
                        <span className={VERDICT_COLOR[r.data!.verdict] ?? "text-gray-300"}>
                          {r.data!.score}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {r.data && (
                        <span
                          className={`text-xs font-semibold ${VERDICT_COLOR[r.data.verdict] ?? "text-gray-500"}`}
                        >
                          {VERDICT_LABEL[r.data.verdict] ?? r.data.verdict}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {r.data && (
                        <Link
                          to={`/history/${r.data.id}`}
                          className="text-xs text-blue-500 hover:text-blue-400 transition"
                        >
                          Ver →
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
