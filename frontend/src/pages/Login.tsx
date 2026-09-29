import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Radar, KeyRound, Loader2 } from "lucide-react";
import { verifyApiKey, setStoredApiKey } from "@/api/client";

export default function Login() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!apiKey.trim()) { setError("Introduce una API key."); return; }
    setLoading(true);
    setError("");
    try {
      const valid = await verifyApiKey(apiKey.trim());
      if (valid) {
        setStoredApiKey(apiKey.trim());
        queryClient.clear();
        navigate("/", { replace: true });
      } else {
        setError("API key incorrecta. Inténtalo de nuevo.");
      }
    } catch {
      setError("No se pudo conectar con el servidor.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{ background: "var(--soc-bg)" }}
    >
      {/* Aurora teal + rejilla de consola */}
      <div
        className="pointer-events-none fixed inset-0"
        style={{
          background:
            "radial-gradient(ellipse 80% 50% at 50% -5%, rgba(45,212,191,0.12) 0%, transparent 70%)",
        }}
      />
      <div
        className="pointer-events-none fixed inset-0 opacity-40"
        style={{
          backgroundImage:
            "linear-gradient(rgba(45,212,191,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(45,212,191,0.03) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative z-10 w-full max-w-sm animate-[fadeSlideIn_0.4s_ease_forwards]">
        {/* Card glassmorphism */}
        <div className="rounded-2xl border border-white/[0.07] bg-white/[0.03] backdrop-blur-sm p-8 shadow-2xl shadow-black/50">
          {/* Logo */}
          <div className="flex flex-col items-center gap-3 mb-8">
            <div className="relative">
              <div className="p-3 rounded-2xl bg-accent/10 border border-accent/20">
                <Radar size={32} className="text-accent" />
              </div>
              <div className="absolute inset-0 rounded-2xl bg-accent/10 blur-xl" />
            </div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-accent-soft to-accent-cyan bg-clip-text text-transparent tracking-tight">
              BlueEcho <span className="font-data text-xs text-accent/50 align-middle">SOC</span>
            </h1>
            <p className="text-sm text-slate-500">Introduce tu API key para acceder</p>
          </div>

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="relative">
              <KeyRound size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" />
              <input
                type="password"
                placeholder="API key"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-slate-900/80 border border-accent/15 text-white placeholder-slate-600 text-sm focus:outline-none focus:border-accent/60 focus:bg-slate-900 transition"
                autoFocus
              />
            </div>

            {error && (
              <p className="text-xs text-red-400 text-center">{error}</p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="flex items-center justify-center gap-2 py-2.5 rounded-lg bg-accent hover:bg-accent-soft disabled:opacity-50 disabled:cursor-not-allowed text-black text-sm font-semibold transition shadow-lg shadow-accent/20"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : "Iniciar sesión"}
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-gray-700 mt-6">
          BlueEcho · Máster en Ciberseguridad 2025-2026
        </p>
      </div>
    </div>
  );
}
