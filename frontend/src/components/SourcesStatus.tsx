import { useQuery } from "@tanstack/react-query";
import { CircleDot } from "lucide-react";
import { getSources } from "@/api/client";
import { cn } from "@/lib/utils";

export default function SourcesStatus() {
  const { data } = useQuery({
    queryKey: ["sources"],
    queryFn: getSources,
    staleTime: 60_000,
  });

  if (!data) return null;

  const active   = data.filter((s) => s.available).length;
  const total    = data.length;

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/50 px-4 py-3">
      <p className="text-xs text-gray-500 mb-2">
        Fuentes activas: <span className="text-gray-300 font-medium">{active}/{total}</span>
      </p>
      <div className="flex flex-wrap gap-2">
        {data.map((s) => (
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
            {s.name}
          </span>
        ))}
      </div>
    </div>
  );
}
