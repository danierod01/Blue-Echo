import { Sparkles } from "lucide-react";

interface Props {
  summary: string;
}

export default function AiSummary({ summary }: Props) {
  if (!summary) return null;

  return (
    <div className="relative pl-4">
      {/* Borde izquierdo luminoso */}
      <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-gradient-to-b from-blue-400 via-cyan-400 to-transparent rounded-full" />

      <div className="flex items-center gap-2 mb-3">
        <Sparkles size={13} className="text-blue-400" />
        <span className="text-[10px] font-semibold text-blue-400 uppercase tracking-widest">
          Análisis IA
        </span>
      </div>

      <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
        {summary}
      </p>
    </div>
  );
}
