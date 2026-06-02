import ReactMarkdown from "react-markdown";
import { Sparkles } from "lucide-react";

interface Props {
  summary: string;
}

export default function AiSummary({ summary }: Props) {
  if (!summary) return null;

  return (
    <div className="rounded-2xl border border-blue-500/10 bg-gradient-to-br from-blue-950/30 to-[#0a0a12] backdrop-blur-sm p-5 shadow-lg shadow-blue-500/5">
      <div className="flex items-center gap-2 mb-3">
        <Sparkles size={16} className="text-blue-400 shrink-0" />
        <h2 className="text-sm font-semibold text-blue-400 uppercase tracking-wider">
          Análisis IA
        </h2>
      </div>
      <div className="text-sm text-gray-200 leading-relaxed prose prose-invert prose-sm max-w-none
        [&_h2]:text-blue-300 [&_h2]:font-semibold [&_h2]:text-xs [&_h2]:uppercase [&_h2]:tracking-wider [&_h2]:mt-4 [&_h2]:mb-1 [&_h2:first-child]:mt-0
        [&_ul]:mt-1 [&_ul]:space-y-0.5 [&_li]:text-gray-300
        [&_strong]:text-white [&_code]:text-blue-300 [&_code]:bg-blue-950/50 [&_code]:px-1 [&_code]:rounded">
        <ReactMarkdown>{summary}</ReactMarkdown>
      </div>
    </div>
  );
}
