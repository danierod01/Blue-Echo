import { useState } from "react";
import { Shield, ChevronDown, ChevronUp, ExternalLink } from "lucide-react";
import type { MitreTechnique } from "@/api/client";

interface Props {
  techniques: MitreTechnique[];
}

const TACTIC_COLOR: Record<string, string> = {
  "Initial Access":       "bg-purple-500/15 text-purple-300 border-purple-500/30",
  "Execution":            "bg-blue-500/15 text-blue-300 border-blue-500/30",
  "Persistence":          "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
  "Defense Evasion":      "bg-orange-500/15 text-orange-300 border-orange-500/30",
  "Credential Access":    "bg-red-500/15 text-red-300 border-red-500/30",
  "Discovery":            "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  "Lateral Movement":     "bg-indigo-500/15 text-indigo-300 border-indigo-500/30",
  "Command and Control":  "bg-teal-500/15 text-teal-300 border-teal-500/30",
  "Exfiltration":         "bg-pink-500/15 text-pink-300 border-pink-500/30",
  "Impact":               "bg-rose-500/15 text-rose-300 border-rose-500/30",
};

const DEFAULT_COLOR = "bg-gray-500/15 text-gray-300 border-gray-500/30";

function TechniqueCard({ t }: { t: MitreTechnique }) {
  const [expanded, setExpanded] = useState(false);
  const color = TACTIC_COLOR[t.tactic] ?? DEFAULT_COLOR;
  const hasDetail = !!(t.reason || t.description);

  return (
    <div className={`rounded-lg border text-xs ${color}`}>
      {/* Cabecera siempre visible */}
      <div className="flex items-center gap-2 px-3 py-2">
        <span className="font-mono font-bold shrink-0">{t.id}</span>
        <span className="font-sans font-medium flex-1">{t.name}</span>
        <a
          href={t.url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="opacity-50 hover:opacity-100 transition shrink-0"
          title="Ver en attack.mitre.org"
        >
          <ExternalLink size={11} />
        </a>
        {hasDetail && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="opacity-50 hover:opacity-100 transition shrink-0"
          >
            {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>
        )}
      </div>

      {/* Detalle expandible */}
      {expanded && hasDetail && (
        <div className="border-t border-current/20 px-3 py-2 space-y-2 font-sans">
          {t.reason && (
            <div>
              <p className="text-[10px] uppercase tracking-wider opacity-60 mb-0.5">Por qué se detectó</p>
              <p className="opacity-90 leading-snug">{t.reason}</p>
            </div>
          )}
          {t.description && (
            <div>
              <p className="text-[10px] uppercase tracking-wider opacity-60 mb-0.5">En qué consiste</p>
              <p className="opacity-75 leading-snug">{t.description}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function MitreAttack({ techniques }: Props) {
  if (!techniques || techniques.length === 0) return null;

  const byTactic: Record<string, MitreTechnique[]> = {};
  for (const t of techniques) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
    byTactic[t.tactic].push(t);
  }

  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-5">
      <div className="flex items-center gap-2 mb-4">
        <Shield size={16} className="text-orange-400" />
        <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
          MITRE ATT&CK — Técnicas identificadas
        </h2>
        <span className="ml-auto text-xs text-gray-600">
          {techniques.length} técnica{techniques.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div className="flex flex-col gap-4">
        {Object.entries(byTactic).map(([tactic, techs]) => (
          <div key={tactic}>
            <p className="text-xs text-gray-600 mb-2">{tactic}</p>
            <div className="flex flex-col gap-1.5">
              {techs.map((t) => (
                <TechniqueCard key={t.id} t={t} />
              ))}
            </div>
          </div>
        ))}
      </div>

      <p className="mt-3 text-xs text-gray-700">
        Haz clic en <ChevronDown size={10} className="inline" /> para ver la evidencia y descripción de cada técnica.
      </p>
    </div>
  );
}
