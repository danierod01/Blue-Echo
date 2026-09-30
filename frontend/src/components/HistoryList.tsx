import { Clock } from "lucide-react";
import { cn, VERDICT_COLOR, VERDICT_LABEL, formatDate } from "@/lib/utils";
import type { HistoryItem } from "@/api/client";
import { TRIAGE_META } from "@/components/TriagePanel";

interface Props {
  items: HistoryItem[];
  onSelect?: (item: HistoryItem) => void;
}

export default function HistoryList({ items, onSelect }: Props) {
  if (items.length === 0) {
    return (
      <p className="text-xs text-gray-600 italic text-center py-4">
        Sin escaneos recientes.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-1">
      {items.map((item) => (
        <li key={item.id}>
          <button
            onClick={() => onSelect?.(item)}
            className="w-full text-left rounded-lg px-3 py-2.5 hover:bg-gray-800 transition group"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-xs text-gray-300 truncate group-hover:text-white transition">
                {item.ioc_value}
              </span>
              <span className={cn("text-xs font-bold tabular-nums shrink-0", VERDICT_COLOR[item.verdict])}>
                {item.score}
              </span>
            </div>
            <div className="flex items-center gap-1 mt-0.5">
              <span className="text-xs text-gray-600 uppercase">{item.ioc_type}</span>
              <span className="text-gray-700">·</span>
              <span className={cn("text-xs font-medium", VERDICT_COLOR[item.verdict])}>
                {VERDICT_LABEL[item.verdict] ?? item.verdict}
              </span>
              <span className="text-gray-700 ml-auto flex items-center gap-1 text-xs text-gray-600">
                <Clock size={10} />
                {formatDate(item.created_at)}
              </span>
            </div>
            {((item.triage && item.triage !== "new") || (item.tags && item.tags.length > 0)) && (
              <div className="flex flex-wrap items-center gap-1 mt-1">
                {item.triage && item.triage !== "new" && TRIAGE_META[item.triage] && (
                  <span
                    className={cn(
                      "rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
                      TRIAGE_META[item.triage].cls,
                    )}
                  >
                    {TRIAGE_META[item.triage].label}
                  </span>
                )}
                {item.tags?.slice(0, 4).map((t) => (
                  <span
                    key={t}
                    className="rounded border border-accent/20 bg-accent/10 px-1.5 py-0.5 font-data text-[10px] text-accent-soft"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </button>
        </li>
      ))}
    </ul>
  );
}
