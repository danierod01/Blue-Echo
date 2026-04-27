import { Sparkles } from "lucide-react";

interface Props {
  summary: string;
}

export default function AiSummary({ summary }: Props) {
  if (!summary) return null;

  return (
    <div className="rounded-2xl border border-blue-900/60 bg-gradient-to-br from-blue-950/40 to-gray-900 p-5">
      <div className="flex items-center gap-2 mb-3">
        <Sparkles size={16} className="text-blue-400 shrink-0" />
        <h2 className="text-sm font-semibold text-blue-400 uppercase tracking-wider">
          Análisis IA
        </h2>
      </div>
      <p className="text-sm text-gray-200 leading-relaxed">{summary}</p>
    </div>
  );
}
