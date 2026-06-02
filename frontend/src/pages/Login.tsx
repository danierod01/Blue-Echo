import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Radar, KeyRound, Loader2 } from "lucide-react";
import { verifyApiKey, setStoredApiKey } from "@/api/client";

export default function Login() {
  const navigate = useNavigate();
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
      style={{ background: "#0a0a12" }}
    >
      {/* Aurora */}
      <div
        className="pointer-events-none fixed inset-0"
        style={{
          background:
            "radial-gradient(ellipse 80% 50% at 50% -5%, rgba(59,130,246,0.12) 0%, transparent 70%)",
        }}
      />

      <div className="relative z-10 w-full max-w-sm animate-[fadeSlideIn_0.4s_ease_forwards]">
        {/* Card glassmorphism */}
        <div className="rounded-2xl border border-white/[0.07] bg-white/[0.03] backdrop-blur-sm p-8 shadow-2xl shadow-black/50">
          {/* Logo */}
          <div className="flex flex-col items-center gap-3 mb-8">
            <div className="relative">
              <div className="p-3 rounded-2xl bg-blue-500/10 border border-blue-500/20">
                <Radar size={32} className="text-blue-400" />
              </div>
              <div className="absolute inset-0 rounded-2xl bg-blue-500/10 blur-xl" />
            </div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent tracking-tight">
              BlueEcho
            </h1>
            <p className="text-sm text-gray-500">Introduce tu API key para acceder</p>
          </div>

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="relative">
              <KeyRound size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" />
              <input
                type="password"
                placeholder="API key"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-gray-900/80 border border-gray-700/60 text-white placeholder-gray-600 text-sm focus:outline-none focus:border-blue-500/60 focus:bg-gray-900 transition"
                autoFocus
              />
            </div>

            {error && (
              <p className="text-xs text-red-400 text-center">{error}</p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="flex items-center justify-center gap-2 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition shadow-lg shadow-blue-500/20"
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
