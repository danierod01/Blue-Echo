import { useState } from "react";
import { ClipboardCheck, Save, X, Tag as TagIcon, Loader2 } from "lucide-react";
import { updateTriage, type TriageState } from "@/api/client";
import { useToast } from "@/components/Toast";
import { cn } from "@/lib/utils";

interface Props {
  scanId: number;
  triage?: TriageState;
  note?: string;
  tags?: string[];
  onUpdated?: (t: { triage: TriageState; note: string; tags: string[] }) => void;
}

export const TRIAGE_META: Record<TriageState, { label: string; cls: string }> = {
  new:            { label: "Nuevo",          cls: "border-slate-600 text-slate-300" },
  investigating:  { label: "Investigando",   cls: "border-accent/50 text-accent" },
  confirmed:      { label: "Confirmado",     cls: "border-red-500/50 text-red-400" },
  false_positive: { label: "Falso positivo", cls: "border-emerald-500/50 text-emerald-400" },
  resolved:       { label: "Resuelto",       cls: "border-slate-500 text-slate-400" },
};

const ORDER: TriageState[] = ["new", "investigating", "confirmed", "false_positive", "resolved"];

export default function TriagePanel({ scanId, triage = "new", note = "", tags = [], onUpdated }: Props) {
  const { toast } = useToast();
  const [state, setState] = useState<TriageState>(triage);
  const [noteVal, setNoteVal] = useState(note);
  const [tagList, setTagList] = useState<string[]>(tags);
  const [tagInput, setTagInput] = useState("");
  const [saving, setSaving] = useState(false);

  function addTag() {
    const t = tagInput.trim().toLowerCase();
    if (t && !tagList.includes(t) && tagList.length < 10) setTagList([...tagList, t]);
    setTagInput("");
  }

  async function save() {
    setSaving(true);
    try {
      await updateTriage(scanId, { triage: state, note: noteVal, tags: tagList });
      onUpdated?.({ triage: state, note: noteVal, tags: tagList });
      toast("Triaje guardado.", "success");
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo guardar el triaje.", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="soc-panel p-4">
      <div className="flex items-center gap-2 mb-3">
        <ClipboardCheck size={14} className="text-accent" />
        <span className="soc-label text-accent">Triaje del analista</span>
      </div>

      {/* Estado */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        {ORDER.map((s) => (
          <button
            key={s}
            onClick={() => setState(s)}
            className={cn(
              "rounded-full border px-2.5 py-1 text-xs font-medium transition",
              state === s ? cn(TRIAGE_META[s].cls, "bg-white/[0.04]") : "border-slate-800 text-slate-500 hover:text-slate-300",
            )}
          >
            {TRIAGE_META[s].label}
          </button>
        ))}
      </div>

      {/* Etiquetas */}
      <div className="flex flex-wrap items-center gap-1.5 mb-2">
        {tagList.map((t) => (
          <span key={t} className="flex items-center gap-1 rounded-md border border-accent/20 bg-accent/10 px-2 py-0.5 font-data text-[11px] text-accent-soft">
            {t}
            <button onClick={() => setTagList(tagList.filter((x) => x !== t))} className="hover:text-white">
              <X size={11} />
            </button>
          </span>
        ))}
        <div className="flex items-center gap-1 rounded-md border border-slate-800 px-2 py-0.5">
          <TagIcon size={11} className="text-slate-600" />
          <input
            value={tagInput}
            onChange={(e) => setTagInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
            placeholder="etiqueta…"
            className="w-24 bg-transparent text-[11px] font-data text-gray-200 placeholder-slate-600 outline-none"
          />
        </div>
      </div>

      {/* Nota */}
      <textarea
        value={noteVal}
        onChange={(e) => setNoteVal(e.target.value)}
        placeholder="Nota del analista (contexto, decisión, siguiente paso)…"
        rows={2}
        className="w-full rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-sm text-gray-200 placeholder-slate-600 outline-none focus:border-accent/40 resize-y"
      />

      <div className="flex justify-end mt-3">
        <button
          onClick={save}
          disabled={saving}
          className="flex items-center gap-2 rounded-lg bg-accent px-4 py-1.5 text-sm font-semibold text-black hover:bg-accent-soft disabled:opacity-50 transition"
        >
          {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
          Guardar triaje
        </button>
      </div>
    </div>
  );
}
