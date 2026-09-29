import { useState } from "react";
import { Radar, Copy, Check, KeyRound, ShieldOff, RefreshCw } from "lucide-react";
import { listTokens, revokeToken, type TokenInfo } from "@/api/client";
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export default function Invite() {
  const [secret, setSecret]   = useState("");
  const [label, setLabel]     = useState("");
  const [expiresDays, setExpiresDays] = useState("");
  const [token, setToken]     = useState<string | null>(null);
  const [error, setError]     = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied]   = useState(false);

  // Panel de gestión de tokens
  const [tokens, setTokens] = useState<TokenInfo[] | null>(null);
  const [manageError, setManageError] = useState<string | null>(null);

  async function loadTokens() {
    setManageError(null);
    try {
      setTokens(await listTokens(secret));
    } catch (err) {
      setManageError(err instanceof Error ? err.message : "Error listando tokens.");
    }
  }

  async function handleRevoke(id: number) {
    setManageError(null);
    try {
      await revokeToken(secret, id);
      await loadTokens();
    } catch (err) {
      setManageError(err instanceof Error ? err.message : "Error revocando token.");
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setToken(null);
    try {
      const res = await fetch(`${API_BASE}/api/auth/invite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          admin_secret: secret,
          label,
          expires_in_days: expiresDays ? Number(expiresDays) : null,
        }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail ?? "Error al generar el token.");
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
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="min-h-screen bg-[#08080f] flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center justify-center gap-2 mb-8">
          <Radar size={22} className="text-blue-400" />
          <span className="font-bold text-lg bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
            BlueEcho
          </span>
        </div>

        <div className="rounded-xl border border-white/8 bg-white/[0.03] p-8">
          <div className="flex items-center gap-2 mb-1">
            <KeyRound size={16} className="text-blue-400" />
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
                type="password"
                value={secret}
                onChange={e => setSecret(e.target.value)}
                placeholder="••••••••••••"
                required
                className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500/60 focus:outline-none focus:ring-1 focus:ring-blue-500/30"
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
                className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500/60 focus:outline-none focus:ring-1 focus:ring-blue-500/30"
              />
              <p className="text-[11px] text-gray-600 mt-1.5">
                Aparecerá en la sesión de quien use este token.
              </p>
            </div>

            <div>
              <label className="block text-xs text-gray-500 mb-1.5 uppercase tracking-wider">
                Caducidad (días) — opcional
              </label>
              <input
                type="number"
                min="1"
                value={expiresDays}
                onChange={e => setExpiresDays(e.target.value)}
                placeholder="Sin caducidad"
                className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500/60 focus:outline-none focus:ring-1 focus:ring-blue-500/30"
              />
            </div>

            {error && (
              <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-4 py-2.5 text-sm font-medium text-white transition"
            >
              {loading ? "Generando…" : "Generar token"}
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

        {/* Panel de gestión de tokens (mismo ADMIN_SECRET del formulario) */}
        <div className="mt-4 rounded-xl border border-white/8 bg-white/[0.03] p-6">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <ShieldOff size={15} className="text-blue-400" />
              <h2 className="text-sm font-semibold text-white">Gestionar tokens</h2>
            </div>
            <button
              onClick={loadTokens}
              disabled={!secret}
              className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white disabled:opacity-40 transition"
              title={secret ? "Cargar tokens" : "Introduce el código de invitación arriba"}
            >
              <RefreshCw size={13} /> Cargar
            </button>
          </div>

          {manageError && (
            <p className="text-xs text-red-400 mb-2">{manageError}</p>
          )}

          {tokens && tokens.length === 0 && (
            <p className="text-xs text-gray-600">No hay tokens emitidos.</p>
          )}

          {tokens && tokens.length > 0 && (
            <ul className="space-y-1.5">
              {tokens.map(t => (
                <li key={t.id} className="flex items-center justify-between gap-2 text-xs border-b border-white/5 pb-1.5">
                  <div className="min-w-0">
                    <span className="text-gray-200">{t.label || "(sin nombre)"}</span>
                    <span className="font-data text-gray-600 ml-2">{t.key_preview}</span>
                    {!t.active && <span className="ml-2 text-red-400">revocado</span>}
                    {t.expires_at && t.active && (
                      <span className="ml-2 text-gray-600">caduca {t.expires_at.slice(0, 10)}</span>
                    )}
                  </div>
                  {t.active && (
                    <button
                      onClick={() => handleRevoke(t.id)}
                      className="shrink-0 text-red-400/80 hover:text-red-400 transition"
                    >
                      Revocar
                    </button>
                  )}
                </li>
              ))}
            </ul>
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
