import { Shield } from "lucide-react";
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

export default function MitreAttack({ techniques }: Props) {
  if (!techniques || techniques.length === 0) return null;

  // Agrupar por táctica para mostrarlas ordenadas
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
        <span className="ml-auto text-xs text-gray-600">{techniques.length} técnica{techniques.length !== 1 ? "s" : ""}</span>
      </div>

      <div className="flex flex-col gap-3">
        {Object.entries(byTactic).map(([tactic, techs]) => (
          <div key={tactic}>
            <p className="text-xs text-gray-600 mb-1.5">{tactic}</p>
            <div className="flex flex-wrap gap-2">
              {techs.map((t) => (
                <a
                  key={t.id}
                  href={t.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={t.source}
                  className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-mono transition hover:opacity-80 ${TACTIC_COLOR[tactic] ?? DEFAULT_COLOR}`}
                >
                  <span className="font-bold">{t.id}</span>
                  <span className="font-sans font-normal opacity-80">{t.name}</span>
                </a>
              ))}
            </div>
          </div>
        ))}
      </div>

      <p className="mt-3 text-xs text-gray-700">
        Atribución basada en hallazgos de conectores TI. Haz clic en cualquier técnica para verla en attack.mitre.org.
      </p>
    </div>
  );
}
