import { useEffect, useState } from "react";
import { X, Copy, Download, Loader2, ShieldBan, Radar } from "lucide-react";
import { getBlockRules, getDetectionRules, type RuleBundle } from "@/api/client";
import { useToast } from "@/components/Toast";
import { cn } from "@/lib/utils";

type Kind = "block" | "detection";

interface Props {
  scanId: number;
  kind: Kind;
  onClose: () => void;
}

const LABELS: Record<string, string> = {
  // bloqueo
  iptables: "iptables", nftables: "nftables", pf: "pf / pfSense",
  cisco: "Cisco ACL", windows: "Windows Firewall", hosts: "hosts",
  unbound: "Unbound", bind_rpz: "BIND RPZ", pihole: "Pi-hole",
  squid: "Squid", note: "Nota",
  // detección
  sigma: "Sigma", suricata: "Suricata", yara: "YARA",
};

const EXT: Record<string, string> = {
  sigma: "yml", suricata: "rules", yara: "yar", hosts: "txt", note: "txt",
};

const META: Record<Kind, { title: string; icon: typeof ShieldBan; blurb: string }> = {
  block: {
    title: "Reglas de bloqueo / respuesta",
    icon: ShieldBan,
    blurb: "Reglas listas para pegar en firewall, DNS o proxy. Revísalas antes de aplicarlas.",
  },
  detection: {
    title: "Reglas de detección",
    icon: Radar,
    blurb: "Convierte el IOC en detección desplegable (Sigma / Suricata / YARA).",
  },
};

export default function RulesModal({ scanId, kind, onClose }: Props) {
  const { toast } = useToast();
  const [bundle, setBundle] = useState<RuleBundle | null>(null);
  const [active, setActive] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const fetcher = kind === "block" ? getBlockRules : getDetectionRules;
    fetcher(scanId)
      .then((b) => {
        if (!alive) return;
        setBundle(b);
        setActive(Object.keys(b.formats)[0] ?? "");
      })
      .catch((e) => alive && setError(e instanceof Error ? e.message : "Error"))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [scanId, kind]);

  // Cerrar con Escape
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const meta = META[kind];
  const Icon = meta.icon;
  const content = active && bundle ? bundle.formats[active] : "";

  async function copy() {
    try {
      await navigator.clipboard.writeText(content);
      toast("Regla copiada al portapapeles.", "success");
    } catch {
      toast("No se pudo copiar.", "error");
    }
  }

  function download() {
    const ext = EXT[active] ?? "txt";
    const safe = (bundle?.ioc ?? String(scanId)).replace(/[^a-zA-Z0-9._-]/g, "_");
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `blue-echo-${safe}-${active}.${ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      onClick={onClose}
    >
      <div
        className="soc-panel w-full max-w-2xl max-h-[85vh] flex flex-col p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 mb-1">
          <div className="flex items-center gap-2">
            <Icon size={16} className="text-accent" />
            <h2 className="soc-label text-accent text-sm">{meta.title}</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition">
            <X size={18} />
          </button>
        </div>
        {bundle && (
          <p className="font-data text-xs text-slate-400 mb-3 break-all">
            {bundle.ioc} <span className="text-slate-600">· {bundle.ioc_type}</span>
          </p>
        )}
        <p className="text-xs text-slate-500 mb-3">{meta.blurb}</p>

        {loading && (
          <div className="flex items-center gap-2 text-slate-400 text-sm py-8 justify-center">
            <Loader2 size={16} className="animate-spin" /> Generando reglas…
          </div>
        )}
        {error && <p className="text-sm text-red-400 py-6 text-center">{error}</p>}

        {!loading && !error && bundle && Object.keys(bundle.formats).length === 0 && (
          <p className="text-sm text-slate-500 py-6 text-center">
            No hay reglas aplicables a este tipo de IOC.
          </p>
        )}

        {!loading && !error && bundle && Object.keys(bundle.formats).length > 0 && (
          <>
            <div className="flex flex-wrap gap-1.5 mb-3">
              {Object.keys(bundle.formats).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => setActive(fmt)}
                  className={cn(
                    "rounded-md border px-2.5 py-1 text-xs font-medium transition",
                    active === fmt
                      ? "border-accent/50 bg-accent/10 text-accent"
                      : "border-slate-800 text-slate-500 hover:text-slate-300",
                  )}
                >
                  {LABELS[fmt] ?? fmt}
                </button>
              ))}
            </div>
            <pre className="flex-1 overflow-auto rounded-lg border border-slate-800 bg-slate-950/70 p-3 font-data text-xs leading-relaxed text-slate-200 whitespace-pre-wrap break-all">
              {content}
            </pre>
            <div className="flex justify-end gap-2 mt-3">
              <button
                onClick={copy}
                className="flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-900/60 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-accent/60 hover:text-accent"
              >
                <Copy size={13} /> Copiar
              </button>
              <button
                onClick={download}
                className="flex items-center gap-2 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-black transition hover:bg-accent-soft"
              >
                <Download size={13} /> Descargar
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
