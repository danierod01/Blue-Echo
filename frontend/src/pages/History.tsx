import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { getHistory } from "@/api/client";
import { cn, VERDICT_COLOR, VERDICT_LABEL, formatDate } from "@/lib/utils";

export default function History() {
  const navigate = useNavigate();
  const { data, isLoading, error } = useQuery({
    queryKey: ["history"],
    queryFn: () => getHistory(50),
  });

  if (isLoading) {
    return (
      <div className="flex justify-center py-16 text-gray-500">
        <Loader2 size={24} className="animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <p className="text-center text-sm text-red-400 py-8">
        Error cargando el historial.
      </p>
    );
  }

  if (!data || data.length === 0) {
    return (
      <p className="text-center text-sm text-gray-600 py-8">
        No hay escaneos en el historial todavía.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-bold text-white">Historial de escaneos</h1>
      <div className="rounded-xl border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-900 text-gray-400 text-xs uppercase tracking-wider">
            <tr>
              <th className="px-4 py-3 text-left">IOC</th>
              <th className="px-4 py-3 text-left">Tipo</th>
              <th className="px-4 py-3 text-left">Score</th>
              <th className="px-4 py-3 text-left">Veredicto</th>
              <th className="px-4 py-3 text-left">Fecha</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {data.map((item) => (
              <tr
                key={item.id}
                className="hover:bg-gray-900/50 transition cursor-pointer"
                onClick={() => navigate(`/history/${item.id}`)}
              >
                <td className="px-4 py-3 font-mono text-gray-200 max-w-xs truncate">
                  {item.ioc_value}
                </td>
                <td className="px-4 py-3 text-gray-500 uppercase text-xs">
                  {item.ioc_type}
                </td>
                <td className="px-4 py-3 font-bold tabular-nums">
                  <span className={cn(VERDICT_COLOR[item.verdict])}>{item.score}</span>
                </td>
                <td className={cn("px-4 py-3 font-semibold text-xs", VERDICT_COLOR[item.verdict])}>
                  {VERDICT_LABEL[item.verdict] ?? item.verdict}
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                  {formatDate(item.created_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
