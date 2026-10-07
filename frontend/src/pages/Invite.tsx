import { useState } from "react";
import { Radar, Copy, Check, KeyRound } from "lucide-react";
import { useToast } from "@/components/Toast";
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export default function Invite() {
  const [code, setCode]       = useState("");
  const [label, setLabel]     = useState("");
  const [token, setToken]     = useState<string | null>(null);
  const [error, setError]     = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied]   = useState(false);
  const { toast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setToken(null);
    try {
      const res = await fetch(`${API_BASE}/api/auth/invite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, label }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail ?? "Error al canjear el código.");
      }
      const data = await res.json();
      setToken(data.token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error desconocido.");
    } finally {
      setLoading(false);
    }
  }

  function copyToken() {
    if (!token) return;
    navigator.clipboard.writeText(token);
    setCopied(true);
    toast("Token copiado al portapapeles.", "success");
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="min-h-screen bg-[var(--soc-bg)] flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center justify-center gap-2 mb-8">
          <Radar size={22} className="text-accent" />
          <span className="font-bold text-lg bg-gradient-to-r from-accent-soft to-accent-cyan bg-clip-text text-transparent">
            BlueEcho
          </span>
        </div>

        <div className="rounded-xl border border-white/8 bg-white/[0.03] p-8">
          <div className="flex items-center gap-2 mb-1">
            <KeyRound size={16} className="text-accent" />
            <h1 className="text-base font-semibold text-white">Obtener acceso</h1>
          </div>
          <p className="text-sm text-gray-500 mb-6">
            Introduce el código de invitación para generar tu token de acceso personal.
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs text-gray-500 mb-1.5 uppercase tracking-wider">
                Código de invitación
              </label>
              <input
                type="text"
                value={code}
                onChange={e => setCode(e.target.value)}
                placeholder="El código que te han dado"
                required
                className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-accent/60 focus:outline-none focus:ring-1 focus:ring-accent/30"
              />
            </div>

            <div>
              <label className="block text-xs text-gray-500 mb-1.5 uppercase tracking-wider">
                Nombre / Identificador
              </label>
              <input
                type="text"
                value={label}
                onChange={e => setLabel(e.target.value)}
                placeholder="p.ej. Profesor García"
                required
                className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-accent/60 focus:outline-none focus:ring-1 focus:ring-accent/30"
              />
              <p className="text-[11px] text-gray-600 mt-1.5">
                Aparecerá en tu sesión.
              </p>
            </div>

            {error && (
              <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-accent hover:bg-accent-soft disabled:opacity-50 px-4 py-2.5 text-sm font-semibold text-black transition"
            >
              {loading ? "Canjeando…" : "Obtener acceso"}
            </button>
          </form>

          {token && (
            <div className="mt-6 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4">
              <p className="text-xs text-emerald-400 mb-2 uppercase tracking-wider">Token generado</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 font-data text-xs text-gray-300 break-all">{token}</code>
                <button
                  onClick={copyToken}
                  className="shrink-0 p-1.5 rounded-md hover:bg-white/5 text-gray-400 hover:text-white transition"
                  title="Copiar"
                >
                  {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                </button>
              </div>
              <p className="text-xs text-gray-600 mt-3">
                Guarda este token — no se puede recuperar después. Úsalo como contraseña en la pantalla de login.
              </p>
            </div>
          )}
        </div>

        <p className="text-center text-xs text-gray-700 mt-4">
          ¿Ya tienes acceso?{" "}
          <a href="/login" className="text-gray-500 hover:text-gray-300 transition">Iniciar sesión</a>
        </p>
      </div>
    </div>
  );
}
